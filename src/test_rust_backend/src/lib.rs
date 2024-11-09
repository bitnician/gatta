mod service;

use alloy::{
    transports::icp::{RpcApi, RpcService},
};
use ic_cdk::export_candid;


fn get_rpc_service_base() -> RpcService {
    // Uncomment to use EVM RPC Canister instead of RPC proxy
    // RpcService::BaseMainnet(L2MainnetService::Alchemy)

    RpcService::Custom(RpcApi {
        url: "https://ic-alloy-evm-rpc-proxy.kristofer-977.workers.dev/base-mainnet".to_string(),
        headers: None,
    })
}


#[ic_cdk::query]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}

export_candid!();