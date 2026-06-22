// Thin CLI over the native verifier: reads the three Cardano-v2 artifacts and runs verify_cardano.
// Used by the full-pipeline e2e (tools/pipeline_e2e.sh) to confirm an INDEPENDENT verifier accepts a
// freshly-proved seal - the on-chain (Aiken/Plutus) verifier checks the same equation.
//
//   verify_cardano <vk.cardano.bin> <proof.cardano.bin> <public.cardano.bin>
//
// Exit: 0 = accepted, 1 = rejected (bad/tampered proof), 2 = usage / IO error.

use std::process::ExitCode;

use groth16_bls_verify::verify_cardano;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: verify_cardano <vk.cardano.bin> <proof.cardano.bin> <public.cardano.bin>");
        return ExitCode::from(2);
    }
    let read = |label: &str, path: &str| match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {label} ({path}): {e}");
            std::process::exit(2);
        }
    };
    let vk = read("vk", &args[1]);
    let proof = read("proof", &args[2]);
    let public = read("public", &args[3]);

    match verify_cardano(&vk, &proof, &public) {
        Ok(()) => {
            println!("VERIFIED: native Rust BLS12-381 Groth16 verify accepted the proof");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("REJECTED: {e:?}");
            ExitCode::FAILURE
        }
    }
}
