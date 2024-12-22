use std::io::Cursor;
use std::sync::Arc;

use anyhow::Context as _;
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
    Info {
        #[arg(help = "Path to the WASM file to inspect")]
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

    fn run(&mut self, seed: u64) -> anyhow::Result<Result<u64, (wasmtime::Trap, String, String)>> {
        *self.stdout.write().unwrap() = Cursor::new(Vec::new());
        *self.stderr.write().unwrap() = Cursor::new(Vec::new());
        let result = match self.test.call(&mut self.store, seed) {
            Ok(r) => r,
            Err(e) => {
                if let Some(trap) = e.root_cause().downcast_ref::<wasmtime::Trap>() {
                    let stdout = String::from_utf8(self.stdout.read().unwrap().get_ref().clone())
                        .unwrap_or_else(|_| "".to_string());
                    let stderr = String::from_utf8(self.stderr.read().unwrap().get_ref().clone())
                        .unwrap_or_else(|_| "".to_string());
                    return Ok(Err((trap.clone(), stdout, stderr)));
                }
                return Err(e);
            }
        };
        self.hll.add(seed, result);
        Ok(Ok(result))
    }

    fn save(&self) -> anyhow::Result<()> {
        save_hll(&format!("{}.json", self.target), &self.hll)?;
        Ok(())
    }
}

fn print_module_info(path: &str) -> anyhow::Result<()> {
    let engine = Engine::default();
    let module = Module::from_file(&engine, path)?;

    println!("Module: {}", path);

    // Extract and print REPO variable
    let mut linker = Linker::new(&engine);
    wasi_common::sync::add_to_linker(&mut linker, |s| s)?;

    let wasi = WasiCtxBuilder::new().build();
    let mut store = Store::new(&engine, wasi);
    let instance = linker.instantiate(&mut store, &module)?;

    let repo_global = instance
        .get_global(&mut store, "REPO")
        .expect("Invalid pot module: REPO global must be exported");
    let offset = repo_global.get(&mut store).i32().unwrap();

    let memory = instance
        .get_memory(&mut store, "memory")
        .context("Invalid pot module: memory export not found")?;

    let repo_string =
        core::ffi::CStr::from_bytes_until_nul(&memory.data(&store)[offset as usize..])
            .unwrap_or_default()
            .to_str()
            .context("Invalid pot module: REPO variable is not valid UTF-8")?;

    println!("Repository: {}", repo_string);

    println!("Exported functions:");
    for export in module.exports() {
        if let Some(func_type) = export.ty().func() {
            let params = func_type
                .params()
                .map(|v| format!("{:?}", v))
                .collect::<Vec<_>>()
                .join(", ");
            let results = func_type
                .results()
                .map(|v| format!("{:?}", v))
                .collect::<Vec<_>>()
                .join(", ");
            println!("  - {}({}) -> {}", export.name(), params, results);
            if export.name() == "test" {
                if params != "i64" || results != "i64" {
                    anyhow::bail!(
                        "Invalid pot module: test functions must have signature test(i64) -> i64"
                    );
                }
            }
        }
    }
    Ok(())
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
                if let Err((trap, stdout, stderr)) = wasm_test.run(seed)? {
                    println!("trap: {trap}\nstdout:\n{}\nstderr:\n{}", stdout, stderr);
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
        Commands::Info { target } => print_module_info(&target),
    }
}
