use std::io::Cursor;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use hyperloglog::HyperLogLog;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use wasi_common::{pipe::WritePipe, sync::WasiCtxBuilder};
use wasmtime::{Engine, Linker, Module, Store};

mod hyperloglog;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Test {
        #[arg(help = "The target to fuzz")]
        target: String,
        #[arg(long, default_value_t = 1_000_000, help = "Number of test iterations")]
        iterations: u64,
        #[arg(long, help = "Optional seed for the test")]
        initial_seed: Option<u64>,
    },
    Verify {
        #[arg(help = "The target to verify")]
        target: String,
    },
}

fn load_hll(path: &str) -> anyhow::Result<HyperLogLog> {
    let file = std::fs::File::open(path)?;
    let hll: HyperLogLog = serde_json::from_reader(file)?;
    Ok(hll)
}

fn save_hll(path: &str, hll: &HyperLogLog) -> anyhow::Result<()> {
    let file = std::fs::File::create(path)?;
    serde_json::to_writer_pretty(file, hll)?;
    Ok(())
}

struct WasmTest {
    target: String,
    hll: HyperLogLog,
    store: wasmtime::Store<wasi_common::WasiCtx>,
    stdout: Arc<std::sync::RwLock<Cursor<Vec<u8>>>>,
    stderr: Arc<std::sync::RwLock<Cursor<Vec<u8>>>>,
    test: wasmtime::TypedFunc<u64, u64>,
}

impl WasmTest {
    fn new(target: &str) -> anyhow::Result<Self> {
        let hll = load_hll(&format!("{}.json", target))
            .ok()
            .unwrap_or(HyperLogLog::new(6));
        let engine = Engine::default();
        let module = Module::from_file(&engine, target)?;
        let mut linker = Linker::new(&engine);
        wasi_common::sync::add_to_linker(&mut linker, |s| s)?;
        let stdout = Arc::new(std::sync::RwLock::new(Cursor::new(Vec::new())));
        let stderr = Arc::new(std::sync::RwLock::new(Cursor::new(Vec::new())));
        let wasi = WasiCtxBuilder::new()
            .stdout(Box::new(WritePipe::from_shared(stdout.clone())))
            .stderr(Box::new(WritePipe::from_shared(stderr.clone())))
            .build();
        let mut store = Store::new(&engine, wasi);
        let instance = linker.instantiate(&mut store, &module)?;
        let test = instance.get_typed_func::<u64, u64>(&mut store, "test")?;
        Ok(Self {
            target: target.to_string(),
            hll,
            store,
            stdout,
            stderr,
            test,
        })
    }

    fn run(&mut self, seed: u64) -> anyhow::Result<Result<u64, String>> {
        *self.stdout.write().unwrap() = Cursor::new(Vec::new());
        *self.stderr.write().unwrap() = Cursor::new(Vec::new());
        let result = self.test.call(&mut self.store, seed)?;
        if result == u64::MAX {
            let stdout = String::from_utf8(self.stdout.read().unwrap().get_ref().clone())?;
            let stderr = String::from_utf8(self.stderr.read().unwrap().get_ref().clone())?;
            return Ok(Err(format!("stdout:\n{}\nstderr:\n{}", stdout, stderr)));
        }
        self.hll.add(seed, result);
        Ok(Ok(result))
    }

    fn save(&self) -> anyhow::Result<()> {
        save_hll(&format!("{}.json", self.target), &self.hll)?;
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Test {
            target,
            iterations,
            initial_seed,
        } => {
            println!("Fuzzing target: {}, iterations: {}", target, iterations);
            let mut wasm_test = WasmTest::new(&target)?;
            println!("Start count: {}", wasm_test.hll.count());

            let mut rng = initial_seed.map_or_else(StdRng::from_entropy, StdRng::seed_from_u64);
            for _ in 0..iterations {
                let seed = rng.gen();
                if let Err(e) = wasm_test.run(seed) {
                    println!("Error: {:?}", e);
                }
            }
            wasm_test.save()?;
            println!("End count: {}", wasm_test.hll.count());
            Ok(())
        }
        Commands::Verify { target } => {
            let mut wasm_test = WasmTest::new(&target)?;
            let hll = wasm_test.hll.clone();
            for (&seed, &hash) in hll.seeds.iter().zip(hll.hashes.iter()) {
                let result = wasm_test.run(seed)?;
                if result != Ok(hash) {
                    println!(
                        "Error: Seed: {}, hash: {}, result: {:?} ❌",
                        seed, hash, result
                    );
                    return Err(anyhow::anyhow!("Verification failed"));
                }
            }
            println!("Verification passed ✅");
            Ok(())
        }
    }
}
