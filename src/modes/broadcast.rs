use console::style;
use std::io;

use crate::cli::Cli;
use crate::ipv4::interface::get_ipv4_interfaces;

pub fn run(cli: &Cli) -> io::Result<()> {
    let requested_interface = cli.target.as_deref();

    let interfaces = get_ipv4_interfaces(requested_interface)?;

    if interfaces.is_empty() {
        match requested_interface {
            Some(name) => {
                eprintln!(
                    "{}",
                    style(format!(
                        "ring: no usable IPv4 broadcast interface named {name}"
                    ))
                    .red()
                    .bold()
                );
            }

            None => {
                eprintln!(
                    "{}",
                    style("ring: no usable IPv4 broadcast interfaces found")
                        .red()
                        .bold()
                );
            }
        }

        std::process::exit(2);
    }

    println!("{}", style("Broadcast interfaces:").magenta().bold());

    for interface in &interfaces {
        println!(
            "{} {} {}",
            style(&interface.name).cyan().bold(),
            style(format!("address={}", interface.address)).green(),
            style(format!("broadcast={}", interface.broadcast))
                .yellow()
                .bold()
        );
    }

    Ok(())
}
