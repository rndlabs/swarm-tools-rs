use clap::Parser;
use swarm_tools::{Cli, run};
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    run(args).await
}
