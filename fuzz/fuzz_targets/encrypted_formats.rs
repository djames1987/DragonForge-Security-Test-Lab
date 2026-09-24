#![no_main]

use dfstl_core::{FuzzTarget, exercise_fuzz_input};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let targets = [
        FuzzTarget::DfVault,
        FuzzTarget::DfBackup,
        FuzzTarget::DfShare,
        FuzzTarget::DfAuth,
    ];
    for target in targets {
        std::hint::black_box(exercise_fuzz_input(target, data));
    }
});
