use std::ops::Deref;

use alloy::{
  contract::{ContractInstance, Interface}, dyn_abi::DynSolValue, network::{Ethereum, EthereumWallet, TransactionBuilder}, primitives::{Address, Bytes, U256}, providers::{Provider, ProviderBuilder}, signers::local::PrivateKeySigner, transports::http::{Client, Http}
};
use eyre::{Error, Result, Report};


pub async fn update_credential(public_values: Vec<u8>, proof_bytes: Vec<u8>) -> Result<()> {
  println!("{:?}", public_values);
  println!("{:?}", proof_bytes);
  let pkey = std::env::var("PRIVATE_KEY")?;
  let rpc_url = std::env::var("RPC_URL")?;
  let contract_address = Address::parse_checksummed(std::env::var("CONTRACT_ADDRESS")?, None)?;
  let path = std::env::current_dir()?.join("artifacts/MDLCityVerifier.json");

  let signer: PrivateKeySigner = pkey.parse().expect("should parse private key");
  let wallet = EthereumWallet::from(signer);

  let artifact = std::fs::read(path).expect("Failed to read artifact");
  let json: serde_json::Value = serde_json::from_slice(&artifact)?;

  let abi_value = json.get("abi").expect("Failed to get ABI from artifact");
  let abi = serde_json::from_str(&abi_value.to_string())?;

  let provider = ProviderBuilder::new()
  .with_recommended_fillers()
  .wallet(wallet)
  .on_http(rpc_url.parse().unwrap());


  let contract: ContractInstance<Http<Client>, _, Ethereum> =
    ContractInstance::new(contract_address, provider.clone(), Interface::new(abi));
  let latest_block = provider.get_block_number().await.unwrap();

  println!("Lastest Block: {:?}", latest_block);

  // let test_address = "0xDF0Ef38272c21BeB470C89b75E3c6754a3C9b90a";
  // let address_value = DynSolValue::from(Address::parse_checksummed(test_address, None)?);
  let public_values_formatted = DynSolValue::from(public_values);
  let proof_bytes_formatted = DynSolValue::from(proof_bytes);
  let update = contract.function("updateCred", &[public_values_formatted, proof_bytes_formatted]).unwrap();
  let update_tx = update.send().await;
  if !update_tx.is_ok() {
    println!("tx failed");
    return Err(Report::msg("Tx failed."));
  } else {
    let confirmed = update_tx.unwrap();
    let hash = confirmed.watch().await.unwrap();
    println!("Tx Hash: {hash}");
  }



  Ok(())
}
