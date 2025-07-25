use core::{cell::RefCell, time::Duration};
use std::{
    borrow::Cow,
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process,
};

use clap::{Arg, ArgAction, Command};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{
        forkserver::{ForkserverExecutor, AFL_MAP_SIZE_ENV_VAR, SHM_CMPLOG_ENV_VAR},
        sand::SANDExecutor,
        StdChildArgs,
    },
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations, token_mutations::I2SRandReplace, tokens_mutations, HavocScheduledMutator,
        StdMOptMutator, Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, StdCmpObserver, StdMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, StdMutationalStage,
        TracingStage,
    },
    state::{HasCorpus, StdState},
    Error, HasMetadata,
};
use libafl_bolts::{
    current_time,
    ownedref::OwnedRefMut,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    tuples::{tuple_list, Handled, Merge},
    AsSliceMut, StdTargetArgs,
};
use libafl_targets::cmps::AflppCmpLogMap;
use nix::sys::signal::Signal;

pub fn main() {
    let res = match Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("AFLplusplus team")
        .about("LibAFL-based fuzzer for Fuzzbench")
        .arg(
            Arg::new("out")
                .short('o')
                .long("output")
                .help("The directory to place finds in ('corpus')"),
        )
        .arg(
            Arg::new("in")
                .short('i')
                .long("input")
                .help("The directory to read initial inputs from ('seeds')"),
        )
        .arg(
            Arg::new("tokens")
                .short('x')
                .long("tokens")
                .help("A file to read tokens from, to be used during fuzzing"),
        )
        .arg(
            Arg::new("logfile")
                .short('l')
                .long("logfile")
                .help("Duplicates all output to this file")
                .default_value("libafl.log"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Timeout for each individual execution, in milliseconds")
                .default_value("1200"),
        )
        .arg(
            Arg::new("exec")
                .help("The instrumented binary we want to fuzz")
                .required(true),
        )
        .arg(
            Arg::new("debug-child")
                .short('d')
                .long("debug-child")
                .help("If not set, the child's stdout and stderror will be redirected to /dev/null")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("signal")
                .short('s')
                .long("signal")
                .help("Signal used to stop child")
                .default_value("SIGKILL"),
        )
        .arg(
            Arg::new("cmplog")
                .short('c')
                .long("cmplog")
                .help("The instrumented binary with cmplog"),
        )
        .arg(
            Arg::new("sand")
                .short('a')
                .long("sand")
                .action(ArgAction::Append),
        )
        .arg(Arg::new("arguments"))
        .try_get_matches()
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, [-x dictionary] -o corpus_dir -i seed_dir\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err,
            );
            return;
        }
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let mut out_dir = PathBuf::from(
        res.get_one::<String>("out")
            .expect("The --output parameter is missing")
            .to_string(),
    );
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }
    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let in_dir = PathBuf::from(
        res.get_one::<String>("in")
            .expect("The --input parameter is missing")
            .to_string(),
    );
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let tokens = res.get_one::<String>("tokens").map(PathBuf::from);

    let logfile = PathBuf::from(res.get_one::<String>("logfile").unwrap().to_string());

    let timeout = Duration::from_millis(
        res.get_one::<String>("timeout")
            .unwrap()
            .to_string()
            .parse()
            .expect("Could not parse timeout in milliseconds"),
    );

    let executable = res
        .get_one::<String>("exec")
        .expect("The executable is missing")
        .to_string();

    let debug_child = res.get_flag("debug-child");

    let signal = str::parse::<Signal>(
        &res.get_one::<String>("signal")
            .expect("The --signal parameter is missing")
            .to_string(),
    )
    .unwrap();

    let cmplog_exec = res
        .get_one::<String>("cmplog")
        .map(std::string::ToString::to_string);

    let arguments = res
        .get_many::<String>("arguments")
        .map(|v| v.map(std::string::ToString::to_string).collect::<Vec<_>>())
        .unwrap_or_default();

    let sands = res.get_many::<String>("sand").map(|t| {
        t.into_iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
    });
    fuzz(
        out_dir,
        crashes,
        &in_dir,
        tokens,
        &logfile,
        timeout,
        executable,
        debug_child,
        signal,
        &cmplog_exec,
        &sands,
        &arguments,
    )
    .expect("An error occurred while fuzzing");
}

/// The actual fuzzer
#[expect(clippy::too_many_arguments)]
fn fuzz(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    seed_dir: &PathBuf,
    tokenfile: Option<PathBuf>,
    logfile: &PathBuf,
    timeout: Duration,
    executable: String,
    debug_child: bool,
    signal: Signal,
    cmplog_exec: &Option<String>,
    sand_execs: &Option<Vec<String>>,
    arguments: &[String],
) -> Result<(), Error> {
    // a large initial map size that should be enough
    // to house all potential coverage maps for our targets
    // (we will eventually reduce the used size according to the actual map)
    const MAP_SIZE: usize = 65_536;

    let log = RefCell::new(OpenOptions::new().append(true).create(true).open(logfile)?);

    // 'While the monitor are state, they are usually used in the broker - which is likely never restarted
    let monitor = SimpleMonitor::new(|s| {
        println!("{s}");
        writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
    });

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // The unix shmem provider for shared memory, to match AFL++'s shared memory at the target side
    let mut shmem_provider = UnixShMemProvider::new().unwrap();

    // The coverage map shared between observer and executor
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    // let the forkserver know the shmid
    unsafe {
        shmem.write_to_env("__AFL_SHM_ID").unwrap();
    }
    let shmem_buf = shmem.as_slice_mut();
    // To let know the AFL++ binary that we have a big map
    std::env::set_var(AFL_MAP_SIZE_ENV_VAR, format!("{}", MAP_SIZE));

    // Create an observation channel using the hitcounts map of AFL++
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
    };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let map_feedback = MaxMapFeedback::new(&edges_observer);

    let calibration = CalibrationStage::new(&edges_observer.handle(), Cow::Borrowed("shared_mem"));

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        map_feedback,
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::new(),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryOnDiskCorpus::<BytesInput>::new(corpus_dir).unwrap(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(objective_dir).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    println!("Let's fuzz :)");

    // Setup a MOPT mutator
    let mutator = StdMOptMutator::new(
        &mut state,
        havoc_mutations().merge(tokens_mutations()),
        7,
        5,
    )?;

    let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
        StdPowerMutationalStage::new(mutator);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        StdWeightedScheduler::with_schedule(
            &mut state,
            &edges_observer,
            Some(PowerSchedule::explore()),
        ),
    );
    let edge_handle = edges_observer.handle();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut tokens = Tokens::new();
    let mut executor = ForkserverExecutor::builder()
        .program(executable)
        .debug_child(debug_child)
        .shmem_provider(&mut shmem_provider)
        .autotokens(&mut tokens)
        .parse_afl_cmdline(arguments)
        .coverage_map_size(MAP_SIZE)
        .timeout(timeout)
        .kill_signal(signal)
        .is_persistent(true)
        .build_dynamic_map(edges_observer, tuple_list!(time_observer))
        .unwrap();

    // Read tokens
    if let Some(tokenfile) = tokenfile {
        tokens.add_from_file(tokenfile)?;
    }
    if !tokens.is_empty() {
        state.add_metadata(tokens);
    }

    state
        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
        .unwrap_or_else(|_| {
            println!("Failed to load initial corpus at {:?}", &seed_dir);
            process::exit(0);
        });
    println!("We imported {} inputs from disk.", state.corpus().count());

    let mut sand_executors = vec![];
    for (idx, sand) in sand_execs
        .as_ref()
        .map(|t| t.iter())
        .into_iter()
        .flatten()
        .enumerate()
    {
        // The extra binaries doesn't need track coverage
        let buf = Box::leak(Box::new(vec![0; MAP_SIZE]));
        let edges_observer = unsafe {
            HitcountsMapObserver::new(StdMapObserver::new(
                format!("dumb_shm_{}", idx),
                buf.as_mut_slice(),
            ))
            .track_indices()
        };
        let time_observer = TimeObserver::new(format!("dumb_tm_{}", idx));
        let executor = ForkserverExecutor::builder()
            .program(sand.clone())
            .debug_child(debug_child)
            .shmem_provider(&mut shmem_provider)
            .parse_afl_cmdline(arguments)
            .coverage_map_size(MAP_SIZE)
            .fsrv_only(true)
            .timeout(timeout)
            .kill_signal(signal)
            .is_persistent(true)
            .build_dynamic_map(edges_observer, tuple_list!(time_observer))
            .unwrap();
        sand_executors.push(executor);
    }
    let mut executor = SANDExecutor::new_paper(executor, sand_executors, edge_handle);

    if let Some(exec) = &cmplog_exec {
        // The cmplog map shared between observer and executor
        let mut cmplog_shmem = shmem_provider.uninit_on_shmem::<AflppCmpLogMap>().unwrap();
        // let the forkserver know the shmid
        unsafe {
            cmplog_shmem.write_to_env(SHM_CMPLOG_ENV_VAR).unwrap();
        }
        let cmpmap = unsafe { OwnedRefMut::<AflppCmpLogMap>::from_shmem(&mut cmplog_shmem) };

        let cmplog_observer = StdCmpObserver::new("cmplog", cmpmap, true);

        let cmplog_executor = ForkserverExecutor::builder()
            .program(exec)
            .debug_child(debug_child)
            .shmem_provider(&mut shmem_provider)
            .parse_afl_cmdline(arguments)
            .is_persistent(true)
            .timeout(timeout * 10)
            .kill_signal(signal)
            .build(tuple_list!(cmplog_observer))
            .unwrap();

        let tracing = TracingStage::new(cmplog_executor);

        // Setup a randomic Input2State stage
        let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
            I2SRandReplace::new()
        )));

        // The order of the stages matter!
        let mut stages = tuple_list!(calibration, tracing, i2s, power);

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    } else {
        // The order of the stages matter!
        let mut stages = tuple_list!(calibration, power);

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    }

    // Never reached
    Ok(())
}
