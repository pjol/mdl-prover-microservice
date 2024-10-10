use std::ops::Deref;

use alloy::{
  network::EthereumWallet, providers::{Provider, ProviderBuilder}, signers::local::PrivateKeySigner
};
use eyre::Result;


pub async fn test_provider() {
  let pkey = std::env::var("OP_PRIVATE_KEY").unwrap_or(String::from("e33fff964dcaa413aed30a0ba1d9725013ec819baf191fb661c0f3b0d7d35e9e"));

  let formatted = pkey.as_str();

  let signer: PrivateKeySigner = formatted.parse().expect("should parse private key");
  let wallet = EthereumWallet::from(signer);

  let rpc_url = "https://sepolia.optimism.io";

  let provider = ProviderBuilder::new()
    .with_recommended_fillers()
    .wallet(wallet)
    .on_http(rpc_url.parse().unwrap());

  let latest_block = provider.get_block_number().await.unwrap();

  println!("Lastest Block: {:?}", latest_block)
}