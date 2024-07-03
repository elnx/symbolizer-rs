// Axel '0vercl0k' Souchet - February 19 2024
#![doc = include_str!("../README.md")]
mod guid;
mod hex_addrs_iter;
mod human;
mod misc;
mod modules;
mod pdbcache;
mod pe;
mod stats;
mod symbolizer;

use std::any::Any;
use std::fmt::Debug;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, io};

use anyhow::{bail, Context, Error, Ok, Result};
use clap::{ArgAction, Parser, ValueEnum};
use guid::Guid;
use kdmp_parser::KernelDumpParser;
use lief::pe::debug::Entries::CodeViewPDB;
use lief::Binary;
use misc::sympath;
use pdb::{
    AddressMap, FallibleIterator, LineProgram, PdbInternalSectionOffset, ProcedureSymbol,
    StringTable, Symbol,
};
use symbolizer::Symbolizer;

/// A PDB opened via file access.
type Pdb<'p> = pdb::PDB<'p, File>;

/// The style of the symbols.
#[derive(Default, Debug, ValueEnum, Clone)]
enum SymbolStyle {
    /// Module + offset style like `foo.dll+0x11`.
    Modoff,
    /// Full symbol style like `foo.dll!func+0x11`.
    #[default]
    Full,
}

/// The command line arguments.
#[derive(Debug, Default, Parser)]
#[command(about = "A fast execution trace symbolizer for Windows.")]
struct CliArgs {
    /// Directory path full of traces or single input trace file.
    #[arg(short, long)]
    trace: PathBuf,
    /// Output directory where to write symbolized traces, a path to an output
    /// file, or empty for the output to go on stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Path to the crash-dump to load. If not specified, an attempt is made to
    /// find a 'state/mem.dmp' file in the same directory than the trace file.
    #[arg(short, long)]
    crash_dump: Option<PathBuf>,
    /// Skip a number of lines.
    #[arg(short, long, default_value_t = 0)]
    skip: usize,
    /// The maximum amount of lines to process per file.
    #[arg(short, long, default_value = "20000000")]
    max: Option<usize>,
    /// The symbolization style (mod+offset or mod!f+offset).
    #[arg(long, default_value = "full")]
    style: SymbolStyle,
    /// Overwrite the output files if they exist.
    #[arg(long, default_value_t = false)]
    overwrite: bool,
    /// Include line numbers in the symbolized output.
    #[arg(long, default_value_t = false)]
    line_numbers: bool,
    /// Symbol servers to use to download PDBs; you can provide more than one.
    #[arg(long, default_value = "https://msdl.microsoft.com/download/symbols/", action = ArgAction::Append)]
    symsrv: Vec<String>,
    /// Specify a symbol cache path. If not specified, _NT_SYMBOL_PATH will be
    /// parsed if present.
    #[arg(long)]
    symcache: Option<PathBuf>,
    /// The size in bytes of the buffer used to write data into the output
    /// files.
    #[arg(long, default_value_t = 3 * 1024 * 1024)]
    out_buffer_size: usize,
    /// The size in bytes of the buffer used to read data from the input files.
    #[arg(long, default_value_t = 1024 * 1024)]
    in_buffer_size: usize,
    /// The PE file path.
    #[arg(short, long)]
    filepath: Option<PathBuf>,
}

fn main() -> Result<()> {
    #[cfg(debug_assertions)]
    env_logger::init();

    // Parse the CLI arguments.
    let args = CliArgs::parse();

    // Figure out what is the symbol path we should be using. We will use the one
    // specified by the user, or will try to find one in the `_NT_SYMBOL_PATH`
    // environment variable if it is defined.
    let Some(symcache) = (match args.symcache.clone() {
        Some(symcache) => Some(symcache),
        None => sympath(),
    }) else {
        bail!("no sympath");
    };

    if let Some(filepath) = &args.filepath {
        let filepath = filepath.to_str().unwrap();

        let mut pdbid = pe::PdbId::default();
        if let Some(Binary::PE(pe)) = Binary::parse(filepath) {
            for entry in pe.debug() {
                if let CodeViewPDB(pdb_view) = entry {
                    eprintln!(
                        "{} {} {}",
                        pdb_view.filename(),
                        pdb_view.age(),
                        pdb_view.guid()
                    );
                    pdbid.age = pdb_view.age();
                    // println!("{}", pdb_view.guid().to_string().as_bytes().len());
                    // let bytes: [u8; 16] = pdb_view.guid().to_string().as_bytes().try_into()?;
                    pdbid.guid = Guid::from_str(pdb_view.guid().to_string().as_str()).unwrap();
                    pdbid.path = PathBuf::from(pdb_view.filename());
                    eprintln!("{}", pdbid);
                    break;
                }
            }
        }

        let pdb_path = symbolizer::get_pdb(&symcache, &args.symsrv.clone(), &pdbid)?;

        if let Some((pdb_path, pdb_kind)) = pdb_path {
            let pdb_path: &std::path::Path = pdb_path.as_ref();
            let pdb_file =
                File::open(pdb_path).with_context(|| format!("failed to open pdb {pdb_path:?}"))?;
            let mut pdb =
                Pdb::open(pdb_file).with_context(|| format!("failed to parse pdb {pdb_path:?}"))?;

            let symbol_table = pdb.global_symbols()?;
            let address_map = pdb.address_map()?;

            let mut symbols = symbol_table.iter();
            while let Some(symbol) = symbols.next()? {
                match symbol.parse() {
                    std::result::Result::Ok(pdb::SymbolData::Public(data)) if data.function||data.code => {
                        // we found the location of a function!
                        let rva = data.offset.to_rva(&address_map).unwrap_or_default();
                        println!("{},{}", data.name, rva);
                    }
                    _ => {}
                }
            }
            eprintln!("pdb download ok: {}", pdb_path.to_str().unwrap());
        }
    }

    return Ok(());

    // Figure out the path to the crash-dump we will use. We will use the one
    // specified by the user, or we will try to find one ourselves.
    let crash_dump_path = if let Some(dump_path) = &args.crash_dump {
        dump_path.clone()
    } else {
        let wtf_base_path = args.trace.parent().expect("parent");
        let wtf_crash_dump_path = wtf_base_path.join("state").join("mem.dmp");
        if !wtf_crash_dump_path.is_file() {
            bail!("A dump file wasn't specified, and a wtf state directory wasn't found either in {wtf_base_path:?}. Please use --crash-dump.");
        }

        println!(
            "A dump file wasn't specified, but found {} so using it..",
            wtf_crash_dump_path.display()
        );

        wtf_crash_dump_path
    };

    // We need to parse the crash-dump to figure out where drivers / user-modules
    // are loaded at, and to read enough information out of the PE to download PDB
    // files ourselves.
    let parser = KernelDumpParser::new(&crash_dump_path).context("failed to create dump parser")?;

    // All right, ready to create the symbolizer.
    let mut symbolizer = Symbolizer::new(symcache, parser, args.symsrv.clone())?;

    symbolizer.start_stopwatch();
    let paths = if args.trace.is_dir() {
        // If we received a path to a directory as input, then we will try to symbolize
        // every file inside that directory..
        let entries = fs::read_dir(&args.trace)?;

        entries
            .map(|e| e.map(|e| e.path()).context(""))
            .collect::<Result<Vec<_>>>()?
    } else {
        // .. or the user specified a path to a file in which case this is the file
        // we'll symbolize.
        vec![args.trace.clone()]
    };

    let total = paths.len();
    for (idx, path) in paths.into_iter().enumerate() {
        print!("\x1B[2K\r");
        symbolizer.process_file(&path, &args)?;
        print!("[{}/{total}] {} done", idx + 1, path.display());
        io::stdout().flush()?;
    }

    // Grab a few stats before exiting!
    let stats = symbolizer.stop_stopwatch();
    println!("\x1B[2K\r{stats}");

    Ok(())
}
