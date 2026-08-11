//! The SM-DP+, as one binary with subcommands -- `serve` among them,
//! the shape Ory Hydra uses.
//!
//! Nothing here holds logic. Each subcommand parses arguments and calls
//! smdp::service, which is what a later admin API will call too.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use smdp::server::{router, ServerConfig};
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
    /// Answer ES9+ over HTTP.
    Serve {
        #[arg(long, default_value = "smdp.db")]
        db: PathBuf,
        /// The address to listen on.
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
        /// This SM-DP+'s own address, as an LPA knows it. Signed into
        /// serverSigned1, and what a received smdpAddress is checked
        /// against (SGP.22 section 5.6.1).
        #[arg(long)]
        server_address: String,
        /// PEM certificate chain. Requires --tls-key.
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// PEM private key. Requires --tls-cert.
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
    },
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

#[tokio::main(flavor = "current_thread")]
async fn serve(
    db: PathBuf,
    addr: String,
    server_address: String,
    tls: Option<(PathBuf, PathBuf)>,
) -> Result<(), String> {
    let store = std::sync::Arc::new(SqliteStore::open(&db).map_err(|e| e.to_string())?);
    let app = router(store, ServerConfig::new(&server_address));
    let bound: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| format!("{addr} is not an address: {e}"))?;

    match tls {
        Some((cert, key)) => {
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                .await
                .map_err(|e| format!("{} / {}: {e}", cert.display(), key.display()))?;
            eprintln!("smdp: listening on https://{bound} as {server_address}");
            axum_server::bind_rustls(bound, config)
                .serve(app.into_make_service())
                .await
                .map_err(|e| e.to_string())
        }
        None => {
            let listener = tokio::net::TcpListener::bind(bound)
                .await
                .map_err(|e| format!("{addr}: {e}"))?;
            // SGP.22 section 6.1 requires TLS on ES9+. A server that
            // quietly speaks cleartext while looking like an SM-DP+ is
            // worse than one that announces it.
            eprintln!(
                "smdp: listening on http://{bound} as {server_address} \
                 -- NO TLS, which SGP.22 section 6.1 requires on ES9+"
            );
            axum::serve(listener, app).await.map_err(|e| e.to_string())
        }
    }
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::Serve {
            db,
            addr,
            server_address,
            tls_cert,
            tls_key,
        } => serve(
            db,
            addr,
            server_address,
            tls_cert.zip(tls_key),
        ),
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
