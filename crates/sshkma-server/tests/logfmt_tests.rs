use proptest::prelude::*;
use sshkma_server::{escape_logfmt_value, unescape_logfmt_value};

#[test]
fn logfmt_roundtrip_simple() {
    let v = "hello world";
    let e = escape_logfmt_value(v);
    assert_eq!(unescape_logfmt_value(&e).unwrap(), v);
}

proptest! {
    #[test]
    fn prop_logfmt_escape_roundtrip(s in ".*") {
        let escaped = escape_logfmt_value(&s);
        let parsed = unescape_logfmt_value(&escaped).unwrap();
        prop_assert_eq!(parsed, s);
    }

    #[test]
    fn prop_logfmt_escaped_no_raw_newline(s in ".*") {
        let escaped = escape_logfmt_value(&s);
        // escaped output must not contain unescaped raw newlines
        // (any newline in output must be within quoted escaped sequence)
        if !s.contains('\n') {
            prop_assert!(!escaped.contains('\n'));
        }
    }
}
