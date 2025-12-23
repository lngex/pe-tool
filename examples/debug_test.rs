use std::{os::raw::c_void, time::Duration};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
fn main() {
    let read = std::fs::read(r"C:\Windows\System32\ntoskrnl.exe").unwrap();

    // let rva = pe_tool::debug::find_func_with_module("LdrpHandleTlsData2", bytes);
    let rva =
        pe_tool::debug::find_func_with_module("ObReferenceProcessHandleTable", read.as_slice());
    if let Some(rva) = rva {
        println!("0x{:x}", rva)
    }
    // let ptr = load_shell_code();
    // println!("分配的地址：{:?}", ptr);
    // unsafe {
    //     std::arch::asm!("call {ptr}",ptr=in(reg)  ptr);
    // }
    // let _ = std::thread::spawn(|| std::thread::sleep(Duration::from_secs(u64::MAX))).join();
}

#[allow(dead_code)]
fn load_shell_code() -> *mut c_void {
    let shell_code = include_bytes!(r"D:\rustProject\venom-rs\target\release\shellcode.bin");
    unsafe {
        let virtual_alloc = windows_sys::Win32::System::Memory::VirtualAlloc(
            std::ptr::null(),
            shell_code.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );
        std::ptr::copy(shell_code.as_ptr(), virtual_alloc as _, shell_code.len());
        virtual_alloc
    }
}
