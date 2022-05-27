use clap::Parser;
use cmd_lib::{init_builtin_logger, run_cmd, spawn};
use color_eyre::Result;

#[derive(Parser)]
struct Arg {
    #[clap(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand)]
enum Action {
    Run {
        #[clap(long)]
        release: bool,
    },
}

fn commit(action: Action) -> Result<()> {
    match action {
        Action::Run { release } => {
            let build_arg = if release { "b --release" } else { "b" };
            run_cmd! {
                cargo $build_arg;
                sudo setcap cap_net_admin=eip target/debug/cft-tcp;
            }?;
            let mut h = spawn! {
                ./target/debug/cft-tcp;
            }?;
            let output = run_cmd! {
                sudo ip addr add 192.168.0.1/24 dev tun0;
                sudo ip link set up dev tun0;
            }?;
            // sudo ip -6 addr flush tun0;
            let output = h.wait()?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    init_builtin_logger();
    let arg: Arg = Arg::parse();
    commit(arg.action)?;
    Ok(())
}
