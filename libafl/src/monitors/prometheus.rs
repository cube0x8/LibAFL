// ===== overview for prommon =====
// The client (i.e., the fuzzer) sets up an HTTP endpoint (/metrics).
// The endpoint contains metrics such as execution rate.

// A prometheus server (can use a precompiled binary or docker) then scrapes \
// the endpoint at regular intervals (configurable via prometheus.yml file).
// ====================
//
// == how to use it ===
// This monitor should plug into any fuzzer similar to other monitors.
// In your fuzzer, include:
// ```rust,ignore
// use libafl::monitors::PrometheusMonitor;
// ```
// as well as:
// ```rust,ignore
// let listener = "127.0.0.1:8080".to_string(); // point prometheus to scrape here in your prometheus.yml
// let mon = PrometheusMonitor::new(listener, |s| log::info!("{s}"));
// and then like with any other monitor, pass it into the event manager like so:
// let mut mgr = SimpleEventManager::new(mon);
// ```
// When using docker, you may need to point prometheus.yml to the docker0 interface or host.docker.internal
// ====================

use alloc::{borrow::Cow, fmt::Debug, string::String, vec::Vec};
use core::{fmt, time::Duration, fmt::Write};
use std::{
    sync::{atomic::AtomicU64, Arc},
    thread,
};
use super::Aggregator;

// using thread in order to start the HTTP server in a separate thread
use futures::executor::block_on;
use libafl_bolts::{current_time, format_duration_hms, ClientId};
// using the official rust client library for Prometheus: https://github.com/prometheus/client_rust
use prometheus_client::{
    encoding::{text::encode, EncodeLabelSet},
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
};
// using tide for the HTTP server library (fast, async, simple)
use tide::Request;

use crate::monitors::{ClientStats, Monitor, UserStatsValue};

/// Tracking monitor during fuzzing.
#[derive(Clone)]
pub struct PrometheusMonitor<F>
where
    F: FnMut(&str),
{
    print_fn: F,
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    corpus_count: Family<Labels, Gauge>,
    objective_count: Family<Labels, Gauge>,
    executions: Family<Labels, Gauge>,
    exec_rate: Family<Labels, Gauge<f64, AtomicU64>>,
    runtime: Family<Labels, Gauge>,
    clients_count: Family<Labels, Gauge>,
    custom_stat: Family<Labels, Gauge<f64, AtomicU64>>,
    global_runtime: Family<Labels, Gauge>,
    global_corpus: Family<Labels, Gauge>,
    global_objectives: Family<Labels, Gauge>,
    global_executions: Family<Labels, Gauge>,
    global_exec_rate: Family<Labels, Gauge<f64, AtomicU64>>,
    global_custom_stat: Family<Labels, Gauge<f64, AtomicU64>>,
    aggregator: Aggregator,
}

impl<F> Debug for PrometheusMonitor<F>
where
    F: FnMut(&str),
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrometheusMonitor")
            .field("start_time", &self.start_time)
            .field("client_stats", &self.client_stats)
            .finish_non_exhaustive()
    }
}

impl<F> Monitor for PrometheusMonitor<F>
where
    F: FnMut(&str),
{
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.start_time
    }

    /// Set creation time
    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    #[allow(clippy::cast_sign_loss)]
    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        // Update the prometheus metrics
        // Label each metric with the sender / client_id
        // The gauges must take signed i64's, with max value of 2^63-1 so it is
        // probably fair to error out at a count of nine quintillion across any
        // of these counts.
        // realistically many of these metrics should be counters but would
        // require a fair bit of logic to handle "amount to increment given
        // time since last observation"
        let sender = format!("#{}", sender_id.0);
        let pad = if event_msg.len() + sender.len() < 13 {
            " ".repeat(13 - event_msg.len() - sender.len())
        } else {
            String::new()
        };
        let head = format!("{event_msg}{pad} {sender}");

        let corpus_size = self.corpus_size();
        self.global_corpus
            .get_or_create(&Labels {
                client: Cow::from("global"),
                stat: Cow::from("corpus_count"),
            })
            .set(corpus_size.try_into().unwrap());
        let objective_size = self.objective_size();
        self.global_objectives
            .get_or_create(&Labels {
                client: Cow::from("global"),
                stat: Cow::from("objectives"),
            })
            .set(objective_size.try_into().unwrap());
        let total_execs = self.total_execs();
        self.global_executions
            .get_or_create(&Labels {
                client: Cow::from("global"),
                stat: Cow::from("executions"),
            })
            .set(total_execs.try_into().unwrap());
        let execs_per_sec = self.execs_per_sec();
        self.global_exec_rate
            .get_or_create(&Labels {
                client: Cow::from("global"),
                stat: Cow::from("execution_rate"),
            })
            .set(execs_per_sec);
        let run_time = (current_time() - self.start_time).as_secs();
        self.global_runtime
            .get_or_create(&Labels {
                client: Cow::from("global"),
                stat: Cow::from("runtime"),
            })
            .set(run_time.try_into().unwrap()); // run time in seconds, which can be converted to a time format by Grafana or similar
        let total_clients = self.client_stats_count().try_into().unwrap(); // convert usize to u64 (unlikely that # of clients will be > 2^64 -1...)
        self.clients_count
            .get_or_create(&Labels {
                client: Cow::from("global"),
                stat: Cow::from("clients_count"),
            })
            .set(total_clients);

        // display aggregated stats
        let mut global_fmt = format!(
            "[Prometheus] [{}] run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            "GLOBAL",
            format_duration_hms(&(current_time() - self.start_time)),
            self.client_stats_count(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec_pretty()
        );

        // display aggregated custom stats
        for (key, val) in &self.aggregator.aggregated {
            write!(global_fmt, ", {key}: {val}").unwrap();
            let value: f64 = match val {
                UserStatsValue::Number(n) => *n as f64,
                UserStatsValue::Float(f) => *f,
                UserStatsValue::String(_s) => 0.0,
                UserStatsValue::Ratio(a, b) => {
                    if key == "edges" {
                        self.global_custom_stat
                            .get_or_create(&Labels {
                                client: Cow::from("global"),
                                stat: Cow::from("edges_total"),
                            })
                            .set(*b as f64);
                        self.global_custom_stat
                            .get_or_create(&Labels {
                                client: Cow::from("global"),
                                stat: Cow::from("edges_hit"),
                            })
                            .set(*a as f64);
                    }
                    (*a as f64 / *b as f64) * 100.0
                }
                UserStatsValue::Percent(p) => *p * 100.0,
            };
            self.global_custom_stat
            .get_or_create(&Labels {
                client: Cow::from("global"),
                stat: Cow::from(key.clone()),
            })
            .set(value);
        }
        (self.print_fn)(&global_fmt);

        // start per-client stats
        self.client_stats_insert(sender_id);
        let cur_client = self.client_stats_mut_for(sender_id);
        let mut cur_client_clone = cur_client.clone();
        let cur_time = current_time();
        let exec_sec = cur_client.execs_per_sec_pretty(cur_time);
        
        let pad = " ".repeat(head.len());
        let mut client_fmt = format!(
            " {} (CLIENT) corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            pad, cur_client.corpus_size, cur_client.objective_size, cur_client.executions, exec_sec
        );

        // client stats
        self.corpus_count
            .get_or_create(&Labels {
                client: Cow::from(sender.clone()),
                stat: Cow::from("corpus_count"),
            })
            .set(cur_client_clone.corpus_size.try_into().unwrap());

        self.objective_count
            .get_or_create(&Labels {
                client: Cow::from(sender.clone()),
                stat: Cow::from("objectives"),
            })
            .set(cur_client_clone.objective_size.try_into().unwrap());

        self.executions
            .get_or_create(&Labels {
                client: Cow::from(sender.clone()),
                stat: Cow::from("executions"),
            })
            .set(cur_client_clone.executions.try_into().unwrap());

        self.exec_rate
            .get_or_create(&Labels {
                client: Cow::from(sender.clone()),
                stat: Cow::from("execution_rate"),
            })
            .set(cur_client_clone.execs_per_sec(cur_time));

        self.runtime
            .get_or_create(&Labels {
                client: Cow::from(sender.clone()),
                stat: Cow::from("runtime"),
            })
            .set((cur_time - cur_client_clone.start_time).as_secs().try_into().unwrap());

        // client custom stats
        for (key, val) in cur_client_clone.user_monitor {
            // Update metrics added to the user_stats hashmap by feedback event-fires
            // You can filter for each custom stat in promQL via labels of both the stat name and client id
            write!(client_fmt, ", {key}: {val}").unwrap();
            #[allow(clippy::cast_precision_loss)]
            let value: f64 = match val.value() {
                UserStatsValue::Number(n) => *n as f64,
                UserStatsValue::Float(f) => *f,
                UserStatsValue::String(_s) => 0.0,
                UserStatsValue::Ratio(a, b) => {
                    if key == "edges" {
                        self.custom_stat
                            .get_or_create(&Labels {
                                client: Cow::from(sender.clone()),
                                stat: Cow::from("edges_total"),
                            })
                            .set(*b as f64);
                        self.custom_stat
                            .get_or_create(&Labels {
                                client: Cow::from(sender.clone()),
                                stat: Cow::from("edges_hit"),
                            })
                            .set(*a as f64);
                    }
                    (*a as f64 / *b as f64) * 100.0
                }
                UserStatsValue::Percent(p) => *p * 100.0,
            };
            self.custom_stat
                .get_or_create(&Labels {
                    client: Cow::from(sender.clone()),
                    stat: key.clone(),
                })
                .set(value);
        }
        (self.print_fn)(&client_fmt);
    }
}

impl<F> PrometheusMonitor<F>
where
    F: FnMut(&str),
{
    pub fn new(listener: String, print_fn: F) -> Self {
        // Gauge's implementation of clone uses Arc
        let corpus_count = Family::<Labels, Gauge>::default();
        let corpus_count_clone = corpus_count.clone();
        let objective_count = Family::<Labels, Gauge>::default();
        let objective_count_clone = objective_count.clone();
        let executions = Family::<Labels, Gauge>::default();
        let executions_clone = executions.clone();
        let exec_rate = Family::<Labels, Gauge<f64, AtomicU64>>::default();
        let exec_rate_clone = exec_rate.clone();
        let runtime: Family<Labels, Gauge> = Family::<Labels, Gauge>::default();
        let runtime_clone = runtime.clone();
        let clients_count = Family::<Labels, Gauge>::default();
        let clients_count_clone = clients_count.clone();
        let custom_stat = Family::<Labels, Gauge<f64, AtomicU64>>::default();
        let custom_stat_clone = custom_stat.clone();

        let aggregator = Aggregator::new();

        let global_runtime = Family::<Labels, Gauge>::default();
        let global_runtime_clone = global_runtime.clone();
        let global_corpus = Family::<Labels, Gauge>::default();
        let global_corpus_clone = global_corpus.clone();
        let global_objectives = Family::<Labels, Gauge>::default();
        let global_objectives_clone = global_objectives.clone();
        let global_executions = Family::<Labels, Gauge>::default();
        let global_executions_clone = global_executions.clone();
        let global_exec_rate = Family::<Labels, Gauge<f64, AtomicU64>>::default();
        let global_exec_rate_clone = global_exec_rate.clone();
        let global_custom_stat = Family::<Labels, Gauge<f64, AtomicU64>>::default();
        let global_custom_stat_clone = global_custom_stat.clone();

        // Need to run the metrics server in a different thread to avoid blocking
        thread::spawn(move || {
            block_on(serve_metrics(
                listener,
                corpus_count_clone,
                objective_count_clone,
                executions_clone,
                exec_rate_clone,
                runtime_clone,
                clients_count_clone,
                custom_stat_clone,
                global_runtime_clone,
                global_corpus_clone,
                global_objectives_clone,
                global_executions_clone,
                global_exec_rate_clone,
                global_custom_stat_clone,
            ))
            .map_err(|err| log::error!("{err:?}"))
            .ok();
        });
        Self {
            print_fn,
            start_time: current_time(),
            client_stats: vec![],
            corpus_count,
            objective_count,
            executions,
            exec_rate,
            runtime,
            clients_count,
            custom_stat,
            global_runtime,
            global_corpus,
            global_objectives,
            global_executions,
            global_exec_rate,
            global_custom_stat,
            aggregator,
        }
    }
    /// Creates the monitor with a given `start_time`.
    pub fn with_time(listener: String, print_fn: F, start_time: Duration) -> Self {
        let corpus_count = Family::<Labels, Gauge>::default();
        let corpus_count_clone = corpus_count.clone();
        let objective_count = Family::<Labels, Gauge>::default();
        let objective_count_clone = objective_count.clone();
        let executions = Family::<Labels, Gauge>::default();
        let executions_clone = executions.clone();
        let exec_rate = Family::<Labels, Gauge<f64, AtomicU64>>::default();
        let exec_rate_clone = exec_rate.clone();
        let runtime: Family<Labels, Gauge> = Family::<Labels, Gauge>::default();
        let runtime_clone = runtime.clone();
        let clients_count = Family::<Labels, Gauge>::default();
        let clients_count_clone = clients_count.clone();
        let custom_stat = Family::<Labels, Gauge<f64, AtomicU64>>::default();
        let custom_stat_clone = custom_stat.clone();
        
        let aggregator = Aggregator::new();

        let global_runtime = Family::<Labels, Gauge>::default();
        let global_runtime_clone = global_runtime.clone();
        let global_corpus = Family::<Labels, Gauge>::default();
        let global_corpus_clone = global_corpus.clone();
        let global_objectives = Family::<Labels, Gauge>::default();
        let global_objectives_clone = global_objectives.clone();
        let global_executions = Family::<Labels, Gauge>::default();
        let global_executions_clone = global_executions.clone();
        let global_exec_rate = Family::<Labels, Gauge<f64, AtomicU64>>::default();
        let global_exec_rate_clone = global_exec_rate.clone();
        let global_custom_stat: Family<Labels, Gauge<f64, AtomicU64>> = Family::<Labels, Gauge<f64, AtomicU64>>::default();
        let global_custom_stat_clone = global_custom_stat.clone();

        thread::spawn(move || {
            block_on(serve_metrics(
                listener,
                corpus_count_clone,
                objective_count_clone,
                executions_clone,
                exec_rate_clone,
                runtime_clone,
                clients_count_clone,
                custom_stat_clone,
                global_runtime_clone,
                global_corpus_clone,
                global_objectives_clone,
                global_executions_clone,
                global_exec_rate_clone,
                global_custom_stat_clone,
            ))
            .map_err(|err| log::error!("{err:?}"))
            .ok();
        });
        Self {
            print_fn,
            start_time,
            client_stats: vec![],
            corpus_count,
            objective_count,
            executions,
            exec_rate,
            runtime,
            clients_count,
            custom_stat,
            global_runtime,
            global_corpus,
            global_objectives,
            global_executions,
            global_exec_rate,
            global_custom_stat,
            aggregator,
        }
    }
}

// set up an HTTP endpoint /metrics
#[allow(clippy::too_many_arguments)]
pub async fn serve_metrics(
    listener: String,
    corpus: Family<Labels, Gauge>,
    objectives: Family<Labels, Gauge>,
    executions: Family<Labels, Gauge>,
    exec_rate: Family<Labels, Gauge<f64, AtomicU64>>,
    runtime: Family<Labels, Gauge>,
    clients_count: Family<Labels, Gauge>,
    custom_stat: Family<Labels, Gauge<f64, AtomicU64>>,
    global_runtime: Family<Labels, Gauge>,
    global_corpus: Family<Labels, Gauge>,
    global_objectives: Family<Labels, Gauge>,
    global_executions: Family<Labels, Gauge>,
    global_exec_rate: Family<Labels, Gauge<f64, AtomicU64>>,
    global_custom_stat: Family<Labels, Gauge<f64, AtomicU64>>,
) -> Result<(), std::io::Error> {
    tide::log::start();

    let mut registry = Registry::default();

    registry.register("corpus_count", "Number of test cases in the corpus", corpus);
    registry.register(
        "objective_count",
        "Number of times the objective has been achieved (e.g., crashes)",
        objectives,
    );
    registry.register(
        "executions_total",
        "Number of executions the fuzzer has done",
        executions,
    );
    registry.register("execution_rate", "Rate of executions per second", exec_rate);
    registry.register("runtime", "How long this client has been running for (seconds)", runtime);
    registry.register(
        "clients_count",
        "How many clients have been spawned for the fuzzing job",
        clients_count,
    );
    registry.register(
        "custom_stat",
        "A metric to contain custom stats returned by feedbacks, filterable by label",
        custom_stat,
    );

    registry.register(
        "global_runtime",
        "How long the fuzzer has been running for (seconds)",
        global_runtime,
    );
    registry.register(
        "global_corpus_count",
        "Number of test cases in the corpus",
        global_corpus,
    );
    registry.register(
        "global_objectives_count",
        "Number of times the objective has been achieved (e.g., crashes)",
        global_objectives,
    );
    registry.register(
        "global_executions_total",
        "Number of executions the fuzzer has done",
        global_executions,
    );
    registry.register(
        "global_execution_rate",
        "Rate of executions per second",
        global_exec_rate,
    );
    registry.register(
        "global_custom_stat",
        "Global custom stats returned by feedbacks, filterable by label",
        global_custom_stat,
    );
    let mut app = tide::with_state(State {
        registry: Arc::new(registry),
    });

    app.at("/")
        .get(|_| async { Ok("LibAFL Prometheus Monitor") });
    app.at("/metrics").get(|req: Request<State>| async move {
        let mut encoded = String::new();
        encode(&mut encoded, &req.state().registry).unwrap();
        let response = tide::Response::builder(200)
            .body(encoded)
            .content_type("application/openmetrics-text; version=1.0.0; charset=utf-8")
            .build();
        Ok(response)
    });
    app.listen(listener).await?;

    Ok(())
}

#[derive(Clone, Hash, PartialEq, Eq, EncodeLabelSet, Debug)]
pub struct Labels {
    client: Cow<'static, str>, // To differentiate between clients when multiple are spawned.
    stat: Cow<'static, str>, // For custom_stat filtering.
}

#[derive(Clone)]
struct State {
    registry: Arc<Registry>,
}
