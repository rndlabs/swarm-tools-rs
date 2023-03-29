use clap::Parser;
use eyre::Result;
use swarm_tools::{run, Cli};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    run(args).await
}
