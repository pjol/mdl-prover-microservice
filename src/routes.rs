use hyper::{body::{Body, Incoming}, Error, Request, Response};
use hyper::body::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt};
use std::path::PathBuf;
use sp1_sdk::{self, HashableKey, SP1ProofWithPublicValues, SP1VerifyingKey};
use sp1_sdk::{ProverClient, SP1Stdin};
use alloy_sol_types::sol;
use alloy_sol_types::SolType;
use jwt_compact::{self, alg::Es256, Algorithm, AlgorithmExt, Token, Claims, UntrustedToken};
use jwt_compact::alg::VerifyingKey;
use super::{mk_response, mk_err};
use serde::{Serialize, Deserialize};
use std::env;
use crate::evm;

type PublicKey = <Es256 as Algorithm>::VerifyingKey;



#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct CredentialSubject {
    #[serde(rename = "type")]
    credential_type: String
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct VerifiableCredential {
    #[serde(rename = "credentialSubject")]
    credential_subject: CredentialSubject
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct VCClaims {
    #[serde(rename = "vc")]
    verifiable_credential: VerifiableCredential,
}

/// Custom claims encoded in the token.
#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct VerifiablePresentation {
    #[serde(rename = "verifiableCredential")]
    verifiable_credential: Vec<String>,
}


#[derive(Debug, PartialEq, Serialize, Deserialize)]

struct VPClaims {
    #[serde(rename = "iss")]
    issuer: String,

    #[serde(rename = "vp")]
    verifiable_presentation: VerifiablePresentation,
    // other fields...
}

#[derive(Serialize, Deserialize)]

struct RequestBody {
    #[serde(rename = "addr")]
    address: String,

    #[serde(rename = "cred")]
    credential: String
}


sol! {
  /// The proof fixture encoded as a struct that can be easily deserialized inside Solidity.
    #[derive(Serialize, Deserialize)]
    struct ProofFixture {
      string proof;
      string values;
      string vkey;
  }
}

sol! {
  struct PublicValues {
      address owner;
      uint256 id;
      uint256 issuedAt;
      string city;
  }
}

//TODO: implement proofs for sig validation && hash match, and derive sig validation vk

pub const FULL_EXECUTION_ELF: &[u8] = include_bytes!("../elf/full_execution/riscv32im-succinct-zkvm-elf");

pub const DMV_PUBLIC_KEY: &[u8] = b"04dedb90c9a9356b144b730097b3dcad4920b89310b8f8f69e661a50bac025237a\
        a38e93622bff867d370ad9150e120e2f72e8b7cb5561606a34f9997e2f7a3d52";

pub async fn prove(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, Error>>, hyper::Error> {
  // Sanity checks first.

  env::set_var("SP1_PROVER", "network");

  if env::var("SP1_PROVER").unwrap() != "network" {
    return mk_err(String::from("use prover network"), hyper::StatusCode::INTERNAL_SERVER_ERROR)
  }



  // Check body size.
  let upper = req.body().size_hint().upper().unwrap_or(u64::MAX);
  if upper > 4096 * 64 {
      return mk_err(String::from("Body too big."), hyper::StatusCode::PAYLOAD_TOO_LARGE);
  }

  // Parse body.
  let cred_bytes = req.collect().await?.to_bytes();
  let ascii = cred_bytes.is_ascii();

  if !ascii {
    return mk_err(String::from("Body malformed."), hyper::StatusCode::BAD_REQUEST);
  }

  let body: Result<RequestBody, serde_json::Error> = serde_json::from_slice(&cred_bytes);
  if !body.is_ok() {
    return mk_err(String::from("Body malformed."), hyper::StatusCode::BAD_REQUEST);
  }

  let b = body.unwrap();

  println!("Address: {}", b.address);
  println!("Checking saneness.");

  // Validate credential outside zkVM before spending all that compute.
  if !check_cred_saneness(&b.credential).is_ok() {
    return mk_err(String::from("Invalid credential."), hyper::StatusCode::BAD_REQUEST);
  }

  println!("Saneness check complete.");

  // Proof time.
  let full_proof = plonk_prove_full_execution(&b.credential, &b.address);
  if !full_proof.is_ok() {
    return mk_err(String::from("Proof failed."), hyper::StatusCode::BAD_REQUEST);
  }

  let (public_values, proof_bytes) = full_proof.unwrap();

  let success = evm::update_credential(public_values, proof_bytes).await;

  if !success.is_ok() {
    return mk_err(String::from("Tx failed."), hyper::StatusCode::INTERNAL_SERVER_ERROR);
  }

  // Returning JSON-ified ProofFixture.
  mk_response(String::from("Success!"))
}

