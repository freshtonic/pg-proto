//! Optimized process entry point for performance-sensitive burn-in commands.

#[tokio::main]
async fn main() {
    if let Err(error) = pg_proto_burn_in::run(std::env::args().collect()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
