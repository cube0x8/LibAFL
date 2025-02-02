#[expect(
    clippy::collapsible_if,
    clippy::manual_assert,
    clippy::missing_panics_doc
)]
pub fn do_thing(data: &[u8]) {
    if data.first() == Some(&b'a') {
        if data.get(1) == Some(&b'b') {
            if data.get(2) == Some(&b'c') {
                if data.get(3) == Some(&b'd') {
                    panic!("We found the objective!");
                }
            }
        }
    }
}
