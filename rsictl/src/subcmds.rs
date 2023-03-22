use crate::tools;
use clap::Args;

pub(crate) type GenericResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) fn version() -> GenericResult
{
    let version = rsictl::abi_version()?;
    println!("{}.{}", version.0, version.1);
    Ok(())
}

#[derive(Args, Debug)]
pub(crate) struct MeasurReadArgs
{
    /// index to read, must be 0-4
    #[arg(short = 'n', long,
          value_parser = clap::value_parser!(u32).range(0..=4))]
    index: u32,

    /// filename to write the measurement, none for stdout hexdump
    #[arg(short, long)]
    output: Option<String>,
}

pub(crate) fn measur_read(args: &MeasurReadArgs) -> GenericResult
{
    rsictl::measurement_read(args.index)?;
    let data = rsictl::dev_read()?;

    match &args.output {
        Some(f) => tools::file_write(f, &data)?,
        None => tools::hexdump(&data, 8, None),
    }

    Ok(())
}

#[derive(Args, Debug)]
pub(crate) struct MeasurExtendArgs
{
    /// index to extend, must be 1-4
    #[arg(short = 'n', long,
          value_parser = clap::value_parser!(u32).range(1..=4))]
    index: u32,

    /// length of random data to use (1-64)
    #[arg(short, long, default_value_t = 64,
          value_parser = clap::value_parser!(u32).range(1..=64))]
    random: u32,

    /// filename to extend the measurement with (1-64 bytes), none to use random
    #[arg(short, long)]
    input: Option<String>,
}

pub(crate) fn measur_extend(args: &MeasurExtendArgs) -> GenericResult
{
    let data = match &args.input {
        None => tools::random_data(args.random as usize),
        Some(f) => tools::file_read(f)?,
    };

    if data.is_empty() || data.len() > 64 {
        println!("Data must be within 1-64 bytes");
        return Err(Box::new(nix::Error::E2BIG));
    }

    rsictl::dev_write(&data)?;
    rsictl::measurement_extend(args.index, data.len().try_into()?)?;

    Ok(())
}

#[derive(Args, Debug)]
pub(crate) struct AttestArgs
{
    /// filename with the challange (64 bytes), none to use random
    #[arg(short, long)]
    input: Option<String>,

    /// filename to write the token to, none for stdout hexdump
    #[arg(short, long)]
    output: Option<String>,
}

pub(crate) fn attest(args: &AttestArgs) -> GenericResult
{
    let challange = match &args.input {
        None => tools::random_data(64),
        Some(f) => tools::file_read(f)?,
    };

    if challange.len() != 64 {
        println!("Challange needs to be exactly 64 bytes");
        return Err(Box::new(nix::Error::E2BIG));
    }

    rsictl::dev_write(&challange)?;
    rsictl::attestation_token()?;
    let token = rsictl::dev_read()?;

    match &args.output {
        None => tools::hexdump(&token, 8, None),
        Some(f) => tools::file_write(f, &token)?,
    }

    Ok(())
}

#[derive(Args, Debug)]
pub(crate) struct DevReadArgs
{
    /// filename to write the measurement, none for stdout hexdump
    #[arg(short, long)]
    output: Option<String>,
}

pub(crate) fn dev_read(args: &DevReadArgs) -> GenericResult
{
    let data = rsictl::dev_read()?;

    match &args.output {
        Some(f) => tools::file_write(f, &data)?,
        None => tools::hexdump(&data, 8, None),
    }

    Ok(())
}
