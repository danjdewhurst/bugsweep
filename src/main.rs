use std::io;

use anyhow::Result;
use bugsweep::cli::{self, Output};
use bugsweep::hardware::Machine;

fn main() -> Result<()> {
    let result = cli::run(
        std::env::args_os().collect(),
        &Machine,
        Output { out: &mut io::stdout(), err: &mut io::stderr() },
    );
    // Help, the version and parse errors end the process as clap prints them.
    if let Err(error) = &result
        && let Some(clap_error) = error.downcast_ref::<clap::Error>()
    {
        clap_error.exit();
    }
    result
}
