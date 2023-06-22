use std::{env, iter, mem, os::windows::prelude::OsStrExt, ptr, time};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, TRUE, WAIT_FAILED},
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
            JobObjectExtendedLimitInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        },
        Threading::{
            CreateProcessW, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED, INFINITE,
            STARTUPINFOW,
        },
    },
};

struct OwnedHandle {
    inner: HANDLE,
}

impl OwnedHandle {
    fn new(handle: HANDLE) -> Self {
        Self { inner: handle }
    }

    fn handle(&self) -> HANDLE {
        self.inner
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.inner);
        }
    }
}

fn main() {
    if env::args_os().len() != 2 {
        eprintln!("USAGE: proc_info <COMMAND>");
        return;
    }
    let job_object = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    assert_ne!(job_object, INVALID_HANDLE_VALUE);
    let job_object = OwnedHandle::new(job_object);
    let mut wide_cmd: Vec<_> = env::args_os()
        .last()
        .unwrap()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let mut startup_info: STARTUPINFOW = unsafe { mem::zeroed() };
    startup_info.cb = mem::size_of_val(&startup_info) as _;
    let mut process_info = mem::MaybeUninit::uninit();
    let ret = unsafe {
        CreateProcessW(
            ptr::null(),
            wide_cmd.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            TRUE,
            CREATE_SUSPENDED,
            ptr::null(),
            ptr::null(),
            &startup_info,
            process_info.as_mut_ptr(),
        )
    };
    assert_ne!(ret, 0);
    let process_info = unsafe { process_info.assume_init() };
    let process_handle = OwnedHandle::new(process_info.hProcess);
    let thread_handle = OwnedHandle::new(process_info.hThread);
    let res = unsafe { AssignProcessToJobObject(job_object.handle(), process_handle.handle()) };
    assert_ne!(res, 0);
    let res = unsafe { ResumeThread(thread_handle.handle()) };
    assert_ne!(res, 0);
    let res = unsafe { WaitForSingleObject(process_handle.handle(), INFINITE) };
    assert_ne!(res, WAIT_FAILED);
    let mut job_object_basic_accounting_info =
        mem::MaybeUninit::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>::uninit();
    let res = unsafe {
        QueryInformationJobObject(
            job_object.handle(),
            JobObjectBasicAccountingInformation,
            job_object_basic_accounting_info.as_mut_ptr().cast(),
            mem::size_of_val(&job_object_basic_accounting_info) as _,
            ptr::null_mut(),
        )
    };
    assert_ne!(res, 0);
    let job_object_basic_accounting_info =
        unsafe { job_object_basic_accounting_info.assume_init() };
    let total_user_time =
        time::Duration::from_nanos(job_object_basic_accounting_info.TotalUserTime as u64 * 100);
    let total_kernel_time =
        time::Duration::from_nanos(job_object_basic_accounting_info.TotalKernelTime as u64 * 100);
    println!("TotalUserTime:         {total_user_time:?}",);
    println!("TotalKernelTime:       {total_kernel_time:?}",);
    println!(
        "TotalTime:             {:?}",
        total_kernel_time + total_user_time
    );

    let mut job_object_extended_limit_info =
        mem::MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::uninit();
    let res = unsafe {
        QueryInformationJobObject(
            job_object.handle(),
            JobObjectExtendedLimitInformation,
            job_object_extended_limit_info.as_mut_ptr().cast(),
            mem::size_of_val(&job_object_extended_limit_info) as _,
            ptr::null_mut(),
        )
    };
    assert_ne!(res, 0);
    let job_object_extended_limit_info = unsafe { job_object_extended_limit_info.assume_init() };
    println!(
        "PeakProcessMemoryUsed: {}",
        bytesize::ByteSize(job_object_extended_limit_info.PeakProcessMemoryUsed as u64)
    );
    println!(
        "PeakJobMemoryUsed:     {}",
        bytesize::ByteSize(job_object_extended_limit_info.PeakJobMemoryUsed as u64)
    );
}
