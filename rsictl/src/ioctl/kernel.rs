/*
 * This file must match kernel API.
 *
 * This includes rsi.h from the rsi module and eventually some internals from
 * the upstream kernel like the version split below.
 */

mod internal
{
    nix::ioctl_read!(abi_version, b'x', 190u8, u32);
    nix::ioctl_write_buf!(measurement_read, b'x', 192u8, u32);
    nix::ioctl_write_buf!(measurement_extend, b'x', 193u8, u32);
    nix::ioctl_none!(attestation_token, b'x', 194u8);
}

pub const fn abi_version_get_major(version: u32) -> u32
{
    version >> 16
}

pub const fn abi_version_get_minor(version: u32) -> u32
{
    version & 0xFFFF
}

pub fn abi_version(fd: i32, data: *mut u32) -> nix::Result<i32>
{
    unsafe { internal::abi_version(fd, data) }
}

pub fn measurement_read(fd: i32, data: &[u32]) -> nix::Result<i32>
{
    unsafe { internal::measurement_read(fd, data) }
}

pub fn measurement_extend(fd: i32, data: &[u32]) -> nix::Result<i32>
{
    unsafe { internal::measurement_extend(fd, data) }
}

pub fn attestation_token(fd: i32) -> nix::Result<i32>
{
    unsafe { internal::attestation_token(fd) }
}
