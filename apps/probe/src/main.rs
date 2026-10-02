//! Each `arg` tries one thing an app must not be able to do. Every one of them should end
//! the app with a fault, not return; returning means the MPU let it through.
//!
//! 0 read firmware RAM          (0x2000_0100, the firmware's .bss)
//! 1 write its own code         (the header's first word)
//! 2 execute its own stack      (a `bx lr` written onto the stack)
//! 3 read a peripheral          (RCC, 0x4002_1000)
//! 4 read flash                 (0x0802_0000, the firmware image)
//! 5 an SVC number it may not use (#0, ENTER)
//! 6 panic                      (exits -1 through the panic handler, not a fault)
#![no_std]
#![no_main]

use catcard_app::sys;

#[unsafe(no_mangle)]
pub extern "C" fn app_main(arg: u32) -> i32 {
    sys::log("probe: trying something forbidden");
    // SAFETY: none of this is safe; that is the point. Each line should fault.
    unsafe {
        match arg {
            0 => {
                core::hint::black_box((0x2000_0100 as *const u32).read_volatile());
            }
            1 => {
                (0x2004_0000 as *mut u32).write_volatile(0);
            }
            2 => {
                let code: [u16; 2] = [0x4770, 0x4770]; // bx lr; bx lr
                let p = core::hint::black_box(code.as_ptr()) as usize | 1;
                let f: extern "C" fn() = core::mem::transmute(p);
                f();
            }
            3 => {
                core::hint::black_box((0x4002_1000 as *const u32).read_volatile());
            }
            4 => {
                core::hint::black_box((0x0802_0000 as *const u32).read_volatile());
            }
            5 => {
                core::arch::asm!("svc #0");
            }
            6 => panic!("on purpose"),
            _ => return -2,
        }
    }
    sys::log("probe: NOT stopped");
    -1000
}
