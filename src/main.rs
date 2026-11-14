use std::io;

use anyhow::Result;
use bugsweep::cli::{self, Output};
use bugsweep::hardware::Machine;

fn main() -> Result<()> {
    cli::run(std::env::args_os(), &Machine, Output { out: &mut io::stdout(), err: &mut io::stderr() })
}
