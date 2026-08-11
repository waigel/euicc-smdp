//! The SM-DP+, as one binary with subcommands -- `serve` among them,
//! the shape Ory Hydra uses.
//!
//! Nothing here holds logic. Each subcommand parses arguments and calls
//! smdp::service, which is what a later admin API will call too.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use smdp::service;
use smdp::store::sqlite::SqliteStore;

#[derive(Parser)]
#[command(name = "smdp", about = "The SM-DP+ of SGP.22", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Profile orders: what an eUICC can come and download.
    #[command(subcommand)]
    Order(OrderCommand),
}

#[derive(Subcommand)]
enum OrderCommand {
    /// Add an order, and print the MatchingID an eUICC needs to claim it.
    Add {
        /// The SQLite file to keep orders in.
        #[arg(long, default_value = "smdp.db")]
        db: PathBuf,
        /// The Unprotected Profile Package to bind.
        #[arg(long)]
        upp: PathBuf,
        /// An encoded StoreMetadataRequest (SGP.22 section 5.5.3).
        ///
        /// A file, not flags: this server cannot encode one yet, so
        /// --profile-name and --sp-name are deliberately not offered
        /// rather than accepted and ignored. euicc-rsp writes a usable
        /// one to testdata/session/store-metadata.der.
        #[arg(long)]
        metadata: PathBuf,
        /// The ICCID, 20 hexadecimal digits.
        #[arg(long)]
        iccid: String,
        /// Use this MatchingID instead of a generated one.
        #[arg(long)]
        matching_id: Option<String>,
        /// The SM-DP+ address, to print an activation code with.
        #[arg(long)]
        host: Option<String>,
    },
    /// List the orders this server knows about.
    List {
        #[arg(long, default_value = "smdp.db")]
        db: PathBuf,
    },
}

fn parse_iccid(s: &str) -> Result<[u8; 10], String> {
    if s.len() != 20 {
        return Err(format!("an ICCID is 20 hexadecimal digits, this is {}", s.len()));
    }
    let mut out = [0u8; 10];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("not hexadecimal at digit {}: {:?}", i * 2 + 1, &s[i * 2..i * 2 + 2]))?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::Order(OrderCommand::Add {
            db,
            upp,
            metadata,
            iccid,
            matching_id,
            host,
        }) => {
            let iccid = parse_iccid(&iccid)?;
            let upp = std::fs::read(&upp).map_err(|e| format!("{}: {e}", upp.display()))?;
            let metadata =
                std::fs::read(&metadata).map_err(|e| format!("{}: {e}", metadata.display()))?;
            let store = SqliteStore::open(&db).map_err(|e| e.to_string())?;
            let order = service::create_order(&store, &iccid, upp, metadata, matching_id)
                .map_err(|e| e.to_string())?;
            println!("order {}", order.id);
            println!("  iccid       {}", hex(&order.iccid));
            println!("  matchingId  {}", order.matching_id);
            if let Some(h) = host {
                println!("  activation  {}", service::activation_code(&h, &order.matching_id));
            }
            Ok(())
        }
        Command::Order(OrderCommand::List { db }) => {
            let store = SqliteStore::open(&db).map_err(|e| e.to_string())?;
            let orders = service::list_orders(&store).map_err(|e| e.to_string())?;
            if orders.is_empty() {
                println!("no orders");
            }
            for o in orders {
                println!(
                    "{:>4}  {:<24}  {}  {:?}{}",
                    o.id,
                    o.matching_id,
                    hex(&o.iccid),
                    o.state,
                    o.eid.map(|e| format!("  eid {e}")).unwrap_or_default()
                );
            }
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("smdp: {e}");
            ExitCode::FAILURE
        }
    }
}
