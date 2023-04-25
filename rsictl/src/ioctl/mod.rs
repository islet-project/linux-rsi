mod kernel;

use nix::{fcntl::OFlag, libc::O_RDWR, sys::stat::Mode};
use std::{
    fs::File,
    io::{Read, Write},
};

const FLAGS: OFlag = OFlag::from_bits_truncate(O_RDWR);
const MODE: Mode = Mode::from_bits_truncate(0o644);
const DEV: &str = "/dev/rsi";


struct Fd
{
    fd: i32,
}

impl Fd
{
    fn wrap(fd: i32) -> Self
    {
        Self { fd }
    }

    fn get(&self) -> i32
    {
        self.fd
    }
}

impl Drop for Fd
{
    fn drop(&mut self)
    {
        match nix::unistd::close(self.fd) {
            Ok(()) => (),
            Err(e) => println!("WARNING: close failed: {}", e),
        }
    }
}

fn dev_read() -> std::io::Result<Vec<u8>>
{
    let mut buf = Vec::<u8>::with_capacity(64);
    File::open(DEV)?.read_to_end(&mut buf)?;
    buf.shrink_to_fit();
    Ok(buf)
}

fn dev_write(data: &[u8]) -> std::io::Result<()>
{
    File::create(DEV)?.write_all(data)
}

pub fn abi_version() -> nix::Result<(u32, u32)>
{
    let fd = Fd::wrap(nix::fcntl::open("/dev/rsi", FLAGS, MODE)?);
    let mut version = 0;
    kernel::abi_version(fd.get(), &mut version)?;
    Ok((
        kernel::abi_version_get_major(version),
        kernel::abi_version_get_minor(version),
    ))
}

pub fn measurement_read(index: u32) -> nix::Result<Vec<u8>>
{
    let fd = Fd::wrap(nix::fcntl::open(DEV, FLAGS, MODE)?);
    kernel::measurement_read(fd.get(), &[index])?;
    std::mem::drop(fd);
    Ok(dev_read().unwrap())
}

pub fn measurement_extend(index: u32, data: &[u8]) -> nix::Result<()>
{
    dev_write(data).unwrap();
    let fd = Fd::wrap(nix::fcntl::open(DEV, FLAGS, MODE)?);
    let data_len = data.len().try_into().or(Err(nix::Error::E2BIG))?;
    kernel::measurement_extend(fd.get(), &[index, data_len])
}

pub fn attestation_token(challenge: &[u8]) -> nix::Result<Vec<u8>>
{
    dev_write(challenge).unwrap();
    let fd = Fd::wrap(nix::fcntl::open(DEV, FLAGS, MODE)?);
    kernel::attestation_token(fd.get())?;
    std::mem::drop(fd);
    Ok(dev_read().unwrap())
}
