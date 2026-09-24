#![no_main]

use dfstl_core::{FuzzTarget, exercise_fuzz_input};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    std::hint::black_box(exercise_fuzz_input(FuzzTarget::WindowsPath, data));
});
