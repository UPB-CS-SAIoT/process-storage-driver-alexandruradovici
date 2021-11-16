//! Print Driver
//! Commands
//!     0 -> SUCCESS
//!     1 -> print buffer
//!     2 -> characters printed
//!
//! Allow
//!     0 -> buffer to display
//!

use kernel::grant::Grant;
use kernel::process::{Error, ProcessId};
use kernel::processbuffer::{ReadOnlyProcessBuffer, ReadableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{debug, ErrorCode};

const BUF_SIZE: usize = 1024;

pub const DRIVER_NUM: usize = 0xa0001;

#[derive(Default)]
pub struct AppStorage {
    counter: u32,
    buffer: ReadOnlyProcessBuffer,
}

pub struct Print {
    grant_access: Grant<AppStorage, 0>,
}

impl Print {
    pub const fn new(grant_access: Grant<AppStorage, 0>) -> Print {
        Print { grant_access }
    }
}

impl SyscallDriver for Print {
    fn command(
        &self,
        command_num: usize,
        _r2: usize,
        _r3: usize,
        process_id: ProcessId,
    ) -> CommandReturn {
        match command_num {
            0 => CommandReturn::success(),
            1 => {
                let res = self
                    .grant_access
                    .enter(process_id, |app_storage, _upcalls_table| {
                        // Result<Result<(), ErrorCode>, Error>
                        let res = app_storage.buffer.enter(|buf| {
                            // buf[index].get() -> u8
                            let mut u8_buffer: [u8; BUF_SIZE] = [0; BUF_SIZE];
                            if buf.len() <= BUF_SIZE {
                                buf.copy_to_slice(&mut u8_buffer[0..buf.len()]);
                                // use r2 to specify how many characters to print
                                let s = core::str::from_utf8(&u8_buffer[0..buf.len()]);
                                if let Ok(s) = s {
                                    debug!("{}", s);
                                    Ok(buf.len() as u32)
                                } else {
                                    Err(ErrorCode::INVAL)
                                }
                            } else {
                                Err(ErrorCode::SIZE)
                            }
                        });
                        match res {
                            Ok(Ok(counter)) => {
                                app_storage.counter = app_storage.counter + counter;
                                Ok(())
                            }
                            Ok(Err(err)) => Err(err),
                            Err(err) => Err(err.into()),
                        }
                    });
                match res {
                    Ok(Ok(())) => CommandReturn::success(),
                    Ok(Err(err)) => CommandReturn::failure(err),
                    Err(err) => CommandReturn::failure(err.into()),
                }
            }
            2 => {
                let res = self
                    .grant_access
                    .enter(process_id, |app_storage, _| app_storage.counter);
                match res {
                    Ok(counter) => CommandReturn::success_u32(counter),
                    Err(err) => CommandReturn::failure(err.into()),
                }
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allow_readonly(
        &self,
        process_id: ProcessId,
        allow_num: usize,
        mut buffer: ReadOnlyProcessBuffer,
    ) -> Result<ReadOnlyProcessBuffer, (ReadOnlyProcessBuffer, ErrorCode)> {
        match allow_num {
            0 => {
                let res = self
                    .grant_access
                    .enter(process_id, |app_storage, _upcalls_table| {
                        core::mem::swap(&mut app_storage.buffer, &mut buffer);
                    });
                match res {
                    Ok(()) => Ok(buffer),
                    Err(err) => Err((buffer, err.into())),
                }
            }
            _ => Err((buffer, ErrorCode::NOSUPPORT)),
        }
    }

    fn allocate_grant(&self, process_id: ProcessId) -> Result<(), Error> {
        self.grant_access
            .enter(process_id, |_app_storage, _upcalls_table| {})
    }
}
