use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::System::Memory::HeapHandle;
use windows_sys::Win32::System::Memory::HEAP_FLAGS;
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR;
use windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_BY_NAME;
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;
use windows_sys::Win32::System::WindowsProgramming::IMAGE_DELAYLOAD_DESCRIPTOR;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DATA_DIRECTORY;

use std::io::Error;

pub type HeapAlloc = unsafe extern "system" fn (HeapHandle, HEAP_FLAGS, usize) -> i32;
pub type GetProcessHeap = unsafe extern "system" fn () -> HeapHandle;
pub type PathFindFileNameW = unsafe extern "system" fn (i32) -> i32;
pub type CreateFileW = unsafe extern "system" fn (isize, u32, u32, isize, u32, u32, isize) -> isize;
pub type GetFileSize = unsafe extern "system" fn (isize, isize) -> u32;
pub type VirtualAlloc = unsafe extern "system" fn (isize, usize, u32, u32) -> isize;
pub type VirtualProtect = unsafe extern "system" fn (isize, usize, u32, *mut u32) -> i32;
pub type ReadFile = unsafe extern "system" fn (isize, isize, u32, isize, isize) -> isize;
pub type LoadLibraryA = unsafe extern "system" fn (isize) -> isize;
pub type FlushInstructionCache = unsafe extern "system" fn (isize, isize, u32) -> i32;
pub type DLLMAIN = unsafe extern "system" fn (isize, u32, isize) -> i32;

//pub type PIMAGE_TLS_CALLBACK = unsafe extern "system" fn(isize, u32, isize);
#[allow(non_camel_case_types)]
pub type PIMAGE_TLS_CALLBACK = Option<unsafe extern "system" fn(dllhandle: isize, reason: u32, reserved: isize)>;

pub const GENERIC_READ: u32 = 2147483648u32;
pub const FILE_SHARE_READ: u32 = 1u32;
pub const FILE_SHARE_WRITE: u32 = 2u32;
pub const OPEN_EXISTING: u32 = 3u32;
pub const INVALID_HANDLE_VALUE: isize = -1i32 as isize;
pub const MEM_COMMIT: u32 = 4096u32;
pub const MEM_RESERVE: u32 = 8192u32;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: u32 = 1;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: u32 = 13u32;
pub const IMAGE_DIRECTORY_ENTRY_TLS: u32 = 9u32;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 536870912u32;
pub const IMAGE_SCN_MEM_READ: u32 = 1073741824u32;
pub const IMAGE_SCN_MEM_WRITE: u32 = 2147483648u32;
pub const PAGE_NOACCESS: u32 = 1u32;
pub const PAGE_WRITECOPY: u32 = 8u32;
pub const PAGE_READONLY: u32 = 2u32;
pub const PAGE_READWRITE: u32 = 4u32;
pub const PAGE_EXECUTE: u32 = 16u32;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 128u32;
pub const PAGE_EXECUTE_READ: u32 = 32u32;
pub const PAGE_EXECUTE_READWRITE: u32 = 64u32;
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 67108864u32;
pub const PAGE_NOCACHE: u32 = 512u32;
pub const DLL_PROCESS_ATTACH: u32 = 1u32;
pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;

// Implementation from:
// https://internals.rust-lang.org/t/get-the-offset-of-a-field-from-the-base-of-a-struct/14163
macro_rules! get_offset {
    ($type:ty, $field:tt) => ({
        let dummy = ::core::mem::MaybeUninit::<$type>::uninit();

        let dummy_ptr = dummy.as_ptr();
        let member_ptr = unsafe{ ::core::ptr::addr_of!((*dummy_ptr).$field) };

        member_ptr as usize - dummy_ptr as usize
    })
}

/// Check if searched by ordinal
#[inline]
#[allow(non_snake_case)]
pub fn IMAGE_SNAP_BY_ORDINAL(ordinal: u64) -> bool {
    (ordinal & IMAGE_ORDINAL_FLAG64) != 0
}

// #[derive(Copy, Clone)]
// struct IMAGE_IMPORT_BY_NAME {
//     hint: u16,
//     name: ,
// }

/// Parse section `characteristics` and return the accrding protections
fn get_section_protection(characteristics: u32) -> u32 {
    let executable = if (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 {true} else {false};
    let readable = if (characteristics & IMAGE_SCN_MEM_READ) != 0 {true} else {false};
    let writeable = if (characteristics & IMAGE_SCN_MEM_WRITE) != 0 {true} else {false};

    if !executable && !readable && !writeable {
        PAGE_NOACCESS
    } else if !executable && !readable && writeable {
        PAGE_WRITECOPY
    } else if !executable && readable && !writeable {
        PAGE_READONLY
    } else if !executable && readable && writeable {
        PAGE_READWRITE
    } else if executable && !readable && !writeable {
        PAGE_EXECUTE
    } else if executable && !readable && writeable {
        PAGE_EXECUTE_WRITECOPY
    } else if executable && readable && !writeable {
        PAGE_EXECUTE_READ
    } else {
        PAGE_EXECUTE_READWRITE
    }
}

pub fn load_library(module_name: &str) {
    // Dynamically resolve some imports:

    // Get base address of kernel32.dll
    let kernel32_base_address: HINSTANCE = peb_walk_rs::get_module_base_addr("kernel32.dll");
    // Get function addresses in kernel32.dll
    let _p_heap_alloc: HeapAlloc = unsafe{
        std::mem::transmute(peb_walk_rs::get_proc_addr(kernel32_base_address, "HeapAlloc"))
    };
    let _p_process_heap: GetProcessHeap = unsafe{
        std::mem::transmute(peb_walk_rs::get_proc_addr(kernel32_base_address, "GetProcessHeap"))
    };
    let p_create_file: CreateFileW = unsafe{
        std::mem::transmute(peb_walk_rs::get_proc_addr(kernel32_base_address, "CreateFileW"))
    };
    let p_get_file_size: GetFileSize = unsafe{
        std::mem::transmute(peb_walk_rs::get_proc_addr(kernel32_base_address, "GetFileSize"))
    };
    let p_virtual_alloc: VirtualAlloc = unsafe{
        std::mem::transmute(peb_walk_rs::get_proc_addr(kernel32_base_address, "VirtualAlloc"))
    };
    let p_virtual_protect: VirtualProtect = unsafe{
        std::mem::transmute(peb_walk_rs::get_proc_addr(kernel32_base_address, "VirtualProtect"))
    };
    let p_read_file: ReadFile = unsafe{
        std::mem::transmute(peb_walk_rs::get_proc_addr(kernel32_base_address, "ReadFile"))
    };
    let p_flush_instruction_cache: FlushInstructionCache = unsafe{
        std::mem::transmute(peb_walk_rs::get_proc_addr(kernel32_base_address, "FlushInstructionCache"))
    };

    //// TODO:
    //// Remove import of "LoadLibraryA" and use custom load_library recursive

    let p_load_library: LoadLibraryA = unsafe{
        std::mem::transmute(peb_walk_rs::get_proc_addr(kernel32_base_address, "LoadLibraryA"))
    };

    // Convert module name string to utf16 byte array
    let mut module_name_utf_16: Vec<u16> = module_name.encode_utf16().collect();

    // Open file based on given module name
    let file_handle = unsafe{
        p_create_file(
            module_name_utf_16.as_mut_ptr() as isize,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            0,
            OPEN_EXISTING,
            0,
            0
        )
    };

    // Check if file successfully opened
    if file_handle == INVALID_HANDLE_VALUE {
        let os_error = Error::last_os_error();
        println!("Failed opening dll file: {os_error:?}");
    }

    // Get file size and allocate a according chunk of memory to load the dll
    let file_size = unsafe{p_get_file_size(file_handle, 0)};

    let p_dll_data = unsafe{
        p_virtual_alloc(
            0,
            file_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )
    };

    // Read dll file into allocated chunk of memeory
    let read_status = unsafe{
        p_read_file(file_handle, p_dll_data, file_size, 0, 0)
    };

    if read_status != 1 {
        let os_error = Error::last_os_error();
        println!("Failed reading dll file: {os_error:?}");
    }
    //// TODO:
    //// Close handle
    //// Check size
    //// Check if module present with same name
    //// Check if valid PE

    // Get DOS header from loaded dll
    let image_dos_header: IMAGE_DOS_HEADER = unsafe{
        *(p_dll_data as *const IMAGE_DOS_HEADER)
    };

    // Get NT header
    let p_image_nt_headers = (p_dll_data + image_dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
    let mut image_nt_headers: IMAGE_NT_HEADERS64 = unsafe{*p_image_nt_headers};

    let mut module_base = image_nt_headers.OptionalHeader.ImageBase as isize;
    let region_size = image_nt_headers.OptionalHeader.SizeOfImage;

    // Try allocate memory at the prefered image base location
    module_base = unsafe{
        p_virtual_alloc(
            module_base as isize,
            region_size as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )
    };

    // If previos allocation failed allocate memory anywhere else
    if module_base == 0 {
        module_base = unsafe{
            p_virtual_alloc(
                0,
                region_size as usize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            )
        };
    }

    // Copy headers to module base location
    for i in 0..image_nt_headers.OptionalHeader.SizeOfHeaders {
        let to = (module_base + i as isize) as *mut [u8; 1];
        let from = (p_dll_data + i as isize) as *const [u8; 1];
        unsafe{ *to = *from; }
    }

    // Get image section header
    let mut p_image_section_header = (p_image_nt_headers as usize +
                                      get_offset!(IMAGE_NT_HEADERS64, OptionalHeader) as usize +
                                      image_nt_headers.FileHeader.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER;
    let mut image_section_header = unsafe{*p_image_section_header};

    // Copy sections to module location
    for _ in 0..image_nt_headers.FileHeader.NumberOfSections {
        for n in 0..unsafe{(*p_image_section_header).SizeOfRawData} {
            let to = (module_base + image_section_header.VirtualAddress as isize + n as isize) as *mut [u8; 1];
            let from = (p_dll_data + image_section_header.PointerToRawData as isize + n as isize) as *const [u8; 1];
            unsafe{ *to = *from; }
        }

        // increment pointer to the next entry
        p_image_section_header = (p_image_section_header as isize +
                                  (std::mem::size_of::<IMAGE_SECTION_HEADER>() as isize)) as *const IMAGE_SECTION_HEADER;
        image_section_header = unsafe{*p_image_section_header};
    }


    //// TODO:
    //// Relocation!
    //// Needs to be done if allocation at prefered image base fails

    // Set ImageBase to loaded module base
    image_nt_headers.OptionalHeader.ImageBase = module_base as u64;

    //// TODO:
    //// Resolve local imports

    // Resolve entry imports
    let data_directory: IMAGE_DATA_DIRECTORY = image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];

    if data_directory.Size != 0 {
        let mut p_image_import_descriptor = (module_base + data_directory.VirtualAddress as isize)
            as *const IMAGE_IMPORT_DESCRIPTOR;
        let mut image_import_decriptor = unsafe{*p_image_import_descriptor};

        loop {
            if image_import_decriptor.Name == 0 {
                break
            }
            //// TODO:
            //// Check if library is present
            //// Use LoadLibrary recursive

            let library_handle = unsafe{p_load_library(module_base + image_import_decriptor.Name as isize)};

            if library_handle == 0 {
                let os_error = Error::last_os_error();
                println!("Failed reading dll file: {os_error:?}");
            }

            // Get FirstThunk as well as OriginalFirstThunk
            // The function addresses in FirstThunk will be overwritten while OriginalFirstThunk will not be touched
            let mut p_first_thunk = (module_base + image_import_decriptor.FirstThunk as isize) as *mut IMAGE_THUNK_DATA64;
            let mut p_orig_first_thunk = (module_base +
                                          unsafe{image_import_decriptor.Anonymous.OriginalFirstThunk as isize}) as *const IMAGE_THUNK_DATA64;

            // Dereference to Rust structs
            let mut orig_first_thunk = unsafe{*p_orig_first_thunk as IMAGE_THUNK_DATA64};

            // Loop over each thunk
            loop {
                // Run until orig_first_thunk.ui.Function is 0
                if unsafe{ orig_first_thunk.u1.Function } == 0 { break }

                if IMAGE_SNAP_BY_ORDINAL(unsafe{orig_first_thunk.u1.Ordinal}){
                    unimplemented!("Search by ordinal not implemented yet");
                }

                let p_import_by_name = unsafe{module_base + orig_first_thunk.u1.AddressOfData as isize} as *const IMAGE_IMPORT_BY_NAME;

                // Get procedure name as string from raw pointer
                let proc_name = unsafe {
                    std::ffi::CStr::from_ptr(
                        (p_import_by_name as usize + std::mem::size_of::<u16>())
                            as *const i8).to_str().unwrap()
                };

                // Get proc address by name
                let proc_address = peb_walk_rs::get_proc_addr(library_handle, proc_name);
                unsafe {(*p_first_thunk).u1.Function = proc_address.unwrap() as u64};

                // Increment first_tunk and orig_first_thunk pointer
                p_first_thunk = (p_first_thunk as usize + std::mem::size_of::<IMAGE_THUNK_DATA64>() as usize) as *mut IMAGE_THUNK_DATA64;
                p_orig_first_thunk = (p_orig_first_thunk as usize + std::mem::size_of::<IMAGE_THUNK_DATA64>() as usize) as *const IMAGE_THUNK_DATA64;

                // Dereference to Rust structs
                orig_first_thunk = unsafe{*p_orig_first_thunk as IMAGE_THUNK_DATA64};
            }

            p_image_import_descriptor = (p_image_import_descriptor as usize +
                                         std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>() as usize) as *const IMAGE_IMPORT_DESCRIPTOR;
            image_import_decriptor = unsafe{*p_image_import_descriptor};
        }
    }

    // Resolve entry delay imports
    let data_directory: IMAGE_DATA_DIRECTORY = image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT as usize];
    if data_directory.Size != 0 {
        // reset import descriptor
        let mut p_image_import_descriptor = (module_base + data_directory.VirtualAddress as isize)
            as *const IMAGE_DELAYLOAD_DESCRIPTOR;
        let mut image_import_decriptor = unsafe{*p_image_import_descriptor};

        loop {
            if image_import_decriptor.DllNameRVA == 0 {
                break
            }
            //// TODO:
            //// Check if library is present
            //// Use LoadLibrary recursive

            let library_handle = unsafe{p_load_library(module_base + image_import_decriptor.DllNameRVA as isize)};

            if library_handle == 0 {
                let os_error = Error::last_os_error();
                println!("Failed reading dll file: {os_error:?}");
            }

            // Get FirstThunk as well as OriginalFirstThunk
            // The function addresses in FirstThunk will be overwritten while OriginalFirstThunk will not be touched
            let mut p_first_thunk = (module_base + image_import_decriptor.ImportAddressTableRVA as isize) as *mut IMAGE_THUNK_DATA64;
            let mut p_orig_first_thunk = (module_base +
                                          image_import_decriptor.ImportNameTableRVA as isize) as *const IMAGE_THUNK_DATA64;

            // Dereference to Rust structs
            let mut orig_first_thunk = unsafe{*p_orig_first_thunk as IMAGE_THUNK_DATA64};

            // Loop over each thunk
            loop {
                // Run until orig_first_thunk.ui.Function is 0
                if unsafe{ orig_first_thunk.u1.Function } == 0 { break }

                if IMAGE_SNAP_BY_ORDINAL(unsafe{orig_first_thunk.u1.Ordinal}){
                    unimplemented!("Search by ordinal not implemented yet");
                }

                let p_import_by_name = unsafe{module_base + orig_first_thunk.u1.AddressOfData as isize} as *const IMAGE_IMPORT_BY_NAME;

                // Get procedure name as string from raw pointer
                let proc_name = unsafe {
                    std::ffi::CStr::from_ptr(
                        (p_import_by_name as usize + std::mem::size_of::<u16>())
                            as *const i8).to_str().unwrap()
                };

                // Get proc address by name
                let proc_address = peb_walk_rs::get_proc_addr(library_handle, proc_name);

                unsafe {(*p_first_thunk).u1.Function = proc_address.unwrap() as u64};

                // Increment first_tunk and orig_first_thunk pointer
                p_first_thunk = (p_first_thunk as usize + std::mem::size_of::<IMAGE_THUNK_DATA64>() as usize) as *mut IMAGE_THUNK_DATA64;
                p_orig_first_thunk = (p_orig_first_thunk as usize + std::mem::size_of::<IMAGE_THUNK_DATA64>() as usize) as *const IMAGE_THUNK_DATA64;

                // Dereference to Rust structs
                orig_first_thunk = unsafe{*p_orig_first_thunk as IMAGE_THUNK_DATA64};
            }

            p_image_import_descriptor = (p_image_import_descriptor as usize +
                                         std::mem::size_of::<IMAGE_DELAYLOAD_DESCRIPTOR>() as usize) as *const IMAGE_DELAYLOAD_DESCRIPTOR;
            image_import_decriptor = unsafe{*p_image_import_descriptor};
        }
    }

    //// TODO:
    //// Link module to PEB

    // Set protections for each section
    // Reset section header to first entry
    p_image_section_header = (p_image_nt_headers as usize +
                              get_offset!(IMAGE_NT_HEADERS64, OptionalHeader) as usize +
                              image_nt_headers.FileHeader.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER;
    image_section_header = unsafe{*p_image_section_header};

    for _ in 0..image_nt_headers.FileHeader.NumberOfSections {
        if image_section_header.SizeOfRawData != 0 {
            let characteristics = image_section_header.Characteristics;
            let mut protection = get_section_protection(characteristics);
            unsafe{
                p_virtual_protect(
                    module_base + image_section_header.VirtualAddress as isize,
                    image_section_header.SizeOfRawData as usize,
                    protection,
                    &mut protection
                );
            }
        }
        // Increment pointer to the next entry
        p_image_section_header = (p_image_section_header as isize +
                                  (std::mem::size_of::<IMAGE_SECTION_HEADER>() as isize)) as *const IMAGE_SECTION_HEADER;
        image_section_header = unsafe{*p_image_section_header};
    }

    unsafe{p_flush_instruction_cache(-1isize, 0, 0)};

    //// TODO:
    //// Fix TLS callback

    //     // Execute TLS callbacks
    //     let data_directory: IMAGE_DATA_DIRECTORY = image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT as usize];

    //     if data_directory.Size != 0 {
    //         println!("Size: {}", data_directory.Size);
    //         let p_image_tls_directory: *const IMAGE_TLS_DIRECTORY32 = (module_base + data_directory.VirtualAddress as isize) as *const IMAGE_TLS_DIRECTORY32;
    //         let image_tls_directory = unsafe{*p_image_tls_directory};
    //         let tls_callbacks = image_tls_directory.AddressOfCallBacks;
    //         let p_tls_callback_function: PIMAGE_TLS_CALLBACK = unsafe{std::mem::transmute(module_base + tls_callbacks as isize)};
    //         let tls_callback_function = p_tls_callback_function.unwrap();
    //         let mut line = String::new();
    //         let _ = std::io::stdin().read_line(&mut line).unwrap();
    //         unsafe{tls_callback_function(module_base, DLL_PROCESS_ATTACH, 0);}
    //     }

    //// TODO:
    //// Check if entry point exists

    // Get DLL entrypoint
    let dll_main: DLLMAIN = unsafe{std::mem::transmute(module_base + image_nt_headers.OptionalHeader.AddressOfEntryPoint as isize)};

    // Call DLL entrypoint
    unsafe{dll_main(module_base, DLL_PROCESS_ATTACH, 0)};
}
