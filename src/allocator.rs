// Linux binaries use mimalloc by default; other targets keep the system allocator.
#[cfg(target_os = "linux")]
use mimalloc::MiMalloc;

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL_ALLOCATOR: MiMalloc = MiMalloc;
