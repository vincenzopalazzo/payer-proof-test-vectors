//! BOLT 12 Payer Proof Test Vector CLI
//!
//! This CLI tool generates and verifies test vectors for BOLT 12 payer proofs
//! as specified in https://github.com/lightning/bolts/pull/1295
//!
//! Uses the rust-lightning implementation from:
//! https://github.com/lightningdevkit/rust-lightning/pull/4297

mod merkle;
mod payer_proof;
mod test_vectors;

use clap::{ArgAction, Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

use test_vectors::{verify_test_vector, TestVectorFile, TestVectorGenerator};

#[derive(Parser)]
#[command(name = "payer-proof-test-vectors")]
#[command(author = "Lightning Network Developers")]
#[command(version = "0.1.0")]
#[command(about = "Generate and verify BOLT 12 payer proof test vectors")]
#[command(
    long_about = "A CLI tool for generating and verifying test vectors for BOLT 12 payer proofs.\n\n\
Based on:\n\
- BOLT spec: https://github.com/lightning/bolts/pull/1295\n\
- Reference implementation: https://github.com/lightningdevkit/rust-lightning/pull/4297"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate test vectors and write to a JSON file
    Generate {
        /// Output file path for the test vectors
        #[arg(short, long, default_value = "test_vectors.json")]
        output: PathBuf,

        /// Random seed for deterministic generation (default: 12345)
        #[arg(long, default_value = "12345")]
        seed: u64,

        /// Number of basic test vectors to generate
        #[arg(long, default_value = "3")]
        basic_count: usize,

        /// Skip test vectors with notes
        #[arg(long, action = ArgAction::SetTrue)]
        no_notes: bool,

        /// Skip invalid/negative test vectors
        #[arg(long, action = ArgAction::SetTrue)]
        no_invalid: bool,
    },

    /// Verify test vectors from a JSON file
    Verify {
        /// Input file path containing test vectors
        #[arg(short, long, default_value = "test_vectors.json")]
        input: PathBuf,

        /// Continue verification even if a test fails
        #[arg(long, action = ArgAction::SetTrue)]
        continue_on_failure: bool,

        /// Verbose output showing each test result
        #[arg(short, long, action = ArgAction::SetTrue)]
        verbose: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            output,
            seed,
            basic_count,
            no_notes,
            no_invalid,
        } => {
            if let Err(e) = generate_test_vectors(output, seed, basic_count, !no_notes, !no_invalid)
            {
                eprintln!("Error generating test vectors: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Verify {
            input,
            continue_on_failure,
            verbose,
        } => {
            if let Err(e) = verify_test_vectors(input, continue_on_failure, verbose) {
                eprintln!("Error verifying test vectors: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn generate_test_vectors(
    output: PathBuf,
    seed: u64,
    basic_count: usize,
    include_notes: bool,
    include_invalid: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating BOLT 12 payer proof test vectors...");
    println!("Using seed: {}\n", seed);

    let generator = TestVectorGenerator::new(seed);
    let mut file = TestVectorFile::new();

    // Generate basic test vectors
    println!("Generating {} basic test vectors...", basic_count);
    for i in 0..basic_count {
        let name = format!("basic_{}", i + 1);
        let description = format!(
            "Basic payer proof with required fields only (test {})",
            i + 1
        );
        // Use different seeds for each vector
        let preimage_seed = (100 + i) as u8;
        let payer_seed = (42 + i) as u8;
        let recipient_seed = (43 + i) as u8;

        match generator.generate_basic_vector(
            &name,
            &description,
            preimage_seed,
            payer_seed,
            recipient_seed,
        ) {
            Ok(vector) => {
                file.add_vector(vector);
                println!("  Generated: {}", name);
            }
            Err(e) => {
                eprintln!("  Failed to generate {}: {}", name, e);
            }
        }
    }

    // Generate vectors with notes
    if include_notes {
        println!("\nGenerating test vectors with notes...");

        let notes = [
            ("with_note_simple", "Payment for coffee"),
            ("with_note_service", "Payment for consulting service"),
            (
                "with_note_long",
                "This is a longer note describing the payment purpose",
            ),
        ];

        for (i, (name, note)) in notes.iter().enumerate() {
            let preimage_seed = (150 + i) as u8;
            let payer_seed = (50 + i) as u8;
            let recipient_seed = (51 + i) as u8;

            match generator.generate_vector_with_note(
                name,
                note,
                preimage_seed,
                payer_seed,
                recipient_seed,
            ) {
                Ok(vector) => {
                    file.add_vector(vector);
                    println!("  Generated: {}", name);
                }
                Err(e) => {
                    eprintln!("  Failed to generate {}: {}", name, e);
                }
            }
        }
    }

    // Generate invalid test vectors
    if include_invalid {
        println!("\nGenerating invalid/negative test vectors...");

        match generator.generate_invalid_preimage_vector(
            "invalid_preimage",
            200, // real preimage seed
            201, // wrong preimage seed
            60,  // payer seed
            61,  // recipient seed
        ) {
            Ok(vector) => {
                file.add_vector(vector);
                println!("  Generated: invalid_preimage");
            }
            Err(e) => {
                eprintln!("  Failed to generate invalid_preimage: {}", e);
            }
        }
    }

    // Always emit the regression vector so every regenerated corpus locks in the
    // BOLT PR #1295 behavior, even when optional categories are skipped.
    println!("\nGenerating mandatory spec regression test vectors...");
    match generator.generate_vector_with_included_experimental_invoice_tlv(
        "included_experimental_invoice_tlv",
        210,
        70,
        71,
    ) {
        Ok(vector) => {
            file.add_vector(vector);
            println!("  Generated: included_experimental_invoice_tlv");
        }
        Err(e) => {
            eprintln!(
                "  Failed to generate included_experimental_invoice_tlv: {}",
                e
            );
        }
    }

    // Serialize and write to file
    let json = serde_json::to_string_pretty(&file)?;
    fs::write(&output, &json)?;

    println!("\n{}", "=".repeat(50));
    println!("Generated {} test vectors", file.vectors.len());
    println!("Output written to: {}", output.display());

    Ok(())
}

fn verify_test_vectors(
    input: PathBuf,
    continue_on_failure: bool,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Verifying BOLT 12 payer proof test vectors...\n");
    println!("Input file: {}\n", input.display());

    let json = fs::read_to_string(&input)?;
    let file: TestVectorFile = serde_json::from_str(&json)?;

    println!("Found {} test vectors", file.vectors.len());
    println!("Version: {}", file.version);
    println!("{}", "=".repeat(60));

    let mut passed = 0;
    let mut failed = 0;
    let mut errors: Vec<(String, String)> = Vec::new();

    for (i, vector) in file.vectors.iter().enumerate() {
        let test_num = i + 1;

        if verbose {
            println!("\nTest {}: {}", test_num, vector.name);
            println!("  Description: {}", vector.description);
            println!("  Expected valid: {}", vector.expected.valid);
        }

        match verify_test_vector(vector) {
            Ok(true) => {
                passed += 1;
                if verbose {
                    println!("  Result: PASSED");
                } else {
                    print!(".");
                }
            }
            Ok(false) => {
                failed += 1;
                let error_msg = "Verification returned false".to_string();
                errors.push((vector.name.clone(), error_msg.clone()));
                if verbose {
                    println!("  Result: FAILED - {}", error_msg);
                } else {
                    print!("F");
                }
                if !continue_on_failure {
                    break;
                }
            }
            Err(e) => {
                failed += 1;
                let error_msg = format!("{}", e);
                errors.push((vector.name.clone(), error_msg.clone()));
                if verbose {
                    println!("  Result: FAILED - {}", error_msg);
                } else {
                    print!("F");
                }
                if !continue_on_failure {
                    break;
                }
            }
        }

        // Flush output for progress dots
        if !verbose {
            use std::io::Write;
            std::io::stdout().flush().unwrap();
        }
    }

    if !verbose {
        println!();
    }

    println!("\n{}", "=".repeat(60));
    println!("\nResults:");
    println!("  Passed: {}", passed);
    println!("  Failed: {}", failed);
    println!("  Total:  {}", passed + failed);

    if !errors.is_empty() {
        println!("\nFailed tests:");
        for (name, error) in &errors {
            println!("  - {}: {}", name, error);
        }
        std::process::exit(1);
    } else {
        println!("\nAll tests passed!");
    }

    Ok(())
}
