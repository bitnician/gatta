use std::{cell::RefCell, time::Duration,str};

use crate::get_rpc_service_base;

use base64::{Engine as _, engine::{self, general_purpose}, alphabet};
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,sign_with_ecdsa
};
use alloy::{
    eips::BlockNumberOrTag,
    primitives::address,
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, Log},
    sol,
    sol_types::SolEvent,
    transports::icp::IcpConfig,
};

use base64::Engine;
// use web3::{signing::recover,signing::RecoveryError,types::Address};


use candid::{CandidType, Principal};
use ic_cdk_timers::TimerId;
use ic_cdk::api::management_canister::ecdsa::{SignWithEcdsaArgument,};
use sha2::Digest;



//* Only 1 request to fetch
const POLL_LIMIT: usize = 1;

struct State {
    timer_id: Option<TimerId>,
    logs: Vec<String>,
    selected_users: Vec<String>,
    poll_count: usize,
}

enum EcdsaKeyIds {
    #[allow(unused)]
    TestKeyLocalDevelopment,
    #[allow(unused)]
    TestKey1,
    #[allow(unused)]
    ProductionKey1,
}

impl EcdsaKeyIds {
    fn to_key_id(&self) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: match self {
                Self::TestKeyLocalDevelopment => "dfx_test_key",
                Self::TestKey1 => "test_key_1",
                Self::ProductionKey1 => "key_1",
            }
            .to_string(),
        }
    }
}

impl State {
    fn default() -> State {
        State {
            // Store the id of the IC_CDK timer used for polling the EVM RPC periodically.
            // This id can be used to cancel the timer before the configured `POLL_LIMIT`
            // has been reached.
            timer_id: None,
            // The logs returned by the EVM are stored here for display in the frontend.
            logs: Vec::new(),
            selected_users: Vec::new(),
            // The number of polls made. Polls finish automatically, once the `POLL_LIMIT`
            // has been reached. This count is used to create a good interactive UI experience.
            poll_count: 0,
        }
    }
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(abi)]
    USDC,
    "abi/USDC.json"
);

/// Using the ICP poller for Alloy allows smart contract canisters
/// to watch EVM blockchain changes easily. In this example, the canister
/// watches for USDC transfer logs.
#[ic_cdk::update]
async fn watch_usdc_transfer_start() -> Result<String, String> {
    // Don't start a timer if one is already running
    STATE.with_borrow(|state| {
        if state.timer_id.is_some() {
            return Err("Already watching for logs.".to_string());
        }
        Ok(())
    })?;

    let rpc_service = get_rpc_service_base();
    let config = IcpConfig::new(rpc_service).set_max_response_size(100_000);
    let provider = ProviderBuilder::new().on_icp(config);

    // This callback will be called every time new logs are received
    let callback = |incoming_logs: Vec<Log>| {
        STATE.with_borrow_mut(|state| {
            for log in incoming_logs.iter() {
                let transfer: Log<USDC::Transfer> = log.log_decode().unwrap();
                let USDC::Transfer { from, to, value } = transfer.data();
                let from_fmt = format!(
                    "0x{}...{}",
                    &from.to_string()[2..5],
                    &from.to_string()[from.to_string().len() - 3..]
                );
                // let to_fmt = format!(
                //     "0x{}...{}",
                //     &to.to_string()[2..5],
                //     &to.to_string()[to.to_string().len() - 3..]
                // );

                    state
                    .logs
                    .push(from_fmt);
            }

            state.poll_count += 1;
            if state.poll_count >= POLL_LIMIT {
                state.timer_id.take();
            }

            ic_cdk::spawn(async move {

  
             });

        })
    };

    // Clear the logs and poll count when starting a new watch
    STATE.with_borrow_mut(|state| {
        state.logs.clear();
        state.poll_count = 0;
    });


    // the address seems to be wrong  
    let usdt_token_address = address!("833589fcd6edb6e08f4c7c32d4f71b54bda02913");
    let filter = Filter::new()
        .address(usdt_token_address)
        // By specifying an `event` or `event_signature` we listen for a specific event of the
        // contract. In this case the `Transfer(address,address,uint256)` event.
        .event(USDC::Transfer::SIGNATURE)
        .from_block(BlockNumberOrTag::Latest);

    // Initialize the poller and start watching
    // `with_limit` (optional) is used to limit the number of times to poll, defaults to 3
    // `with_poll_interval` (optional) is used to set the interval between polls, defaults to 7 seconds
    let poller = provider.watch_logs(&filter).await.unwrap();
    let timer_id = poller
        .with_limit(Some(POLL_LIMIT))
        .with_poll_interval(Duration::from_secs(10))
        .start(callback)
        .unwrap();

    // Save timer id to be able to stop watch before completion
    STATE.with_borrow_mut(|state| {
        state.timer_id = Some(timer_id);
    });
    
    Ok(format!("Watching for logs, polling {} times.", POLL_LIMIT))
}

/// Stop the watch before it reaches completion
#[ic_cdk::update]
async fn watch_usdc_transfer_stop() -> Result<String, String> {
    STATE.with_borrow_mut(|state| {
        if let Some(timer_id) = state.timer_id.take() {
            ic_cdk_timers::clear_timer(timer_id);
            Ok(())
        } else {
            Err("No timer to clear.".to_string())
        }
    })?;

    Ok("Watching for logs stopped.".to_string())
}

/// Returns a boolean that is `true` when watching and `false` otherwise.
#[ic_cdk::query]
async fn watch_usdc_transfer_is_polling() -> Result<bool, String> {
    STATE.with_borrow(|state| Ok(state.timer_id.is_some()))
}

/// Returns the number of polls made. Polls finish automatically, once the `POLL_LIMIT`
/// has been reached. This count is used to create a good interactive UI experience.
#[ic_cdk::query]
async fn watch_usdc_transfer_poll_count() -> Result<usize, String> {
    STATE.with_borrow(|state| Ok(state.poll_count))
}

/// Returns the list of logs returned by the watch. Gets reset on each start.
#[ic_cdk::query]
async fn watch_usdc_transfer_get() -> Result<Vec<String>, String> {
    STATE.with_borrow(|state| Ok(state.logs.iter().map(|log| format!("{log:?}")).collect()))
}


async fn select_random_values(target: &Vec<String>, count: usize) -> Vec<String> {
    let (random_bytes,): (Vec<u8>,) = ic_cdk::call(Principal::management_canister(), "raw_rand", ()).await.unwrap();

    let mut selected = Vec::new();
    let target_len: usize = target.len();

    for i in 0..count {
        // Use the random data to get an index within the target's bounds
        let index = random_bytes[i % random_bytes.len()] as usize % target_len;
        selected.push(target[index].clone());
    }

    selected
}

#[ic_cdk::update]
async fn watch_selected_users(count: usize) -> Result<Vec<String>, String> {
    // Call `watch_usdc_transfer_get()` and handle the Result
    let selected = match watch_usdc_transfer_get().await {
        Ok(users) => users,                    // If successful, get the Vec<String>
        Err(e) => return Err(e),               // If there’s an error, return it as Err
    };

    // Call `select_random_values` and wrap its result in `Ok`
    Ok(select_random_values(&selected, count).await)
}


// ** Generating Voucher **/

fn sha256(input: &String) -> [u8; 32] {
    
    let mut hasher = sha2::Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().into()
}


#[ic_cdk::update]
async fn get_public_key() -> Vec<u8>{

    let request = EcdsaPublicKeyArgument {
      canister_id: None, 
      derivation_path: vec![],
      key_id: EcdsaKeyIds::ProductionKey1.to_key_id(),
    };
    
    let (response,) = ecdsa_public_key(request)
      .await
      .expect("ecdsa_public_key failed");
    
    response.public_key
}



#[ic_cdk::update]
async fn generate_voucher()->  Vec<u8> {
    let (random_bytes,): (Vec<u8>,) = ic_cdk::call(Principal::management_canister(), "raw_rand", ()).await.unwrap();

    let hex_string = hex::encode(&random_bytes);
    let message_hash = sha256(&hex_string).to_vec();


    let request = SignWithEcdsaArgument {
        message_hash,
        derivation_path: vec![],
        key_id: EcdsaKeyIds::ProductionKey1.to_key_id(),
    };

    let (response,) = sign_with_ecdsa(request)
    .await
    .expect("sign_with_ecdsa failed");

    return response.signature;
}

#[ic_cdk::query]
async fn gnenrate_signature(addr: String) -> Result<bool, String> {
    // Check if the address exists in the logs
    let is_found = STATE.with(|state| {
        let logs = &state.borrow().logs;
        logs.contains(&addr)
    });



    if is_found {
        // Perform the desired action here
        // Example: Emit a log message
        ic_cdk::println!("Address {} found. Performing action.", addr.to_string());

        // You can add more complex logic here as needed
        // For example, updating another part of the state, triggering other functions, etc.

        Ok(true)
    } else {
        Err("Address not found in logs.".to_string())
    }
}

//** Signature Verification **/ 
// fn recover_signature(    
//     message: &[u8],
//     signature: &[u8],
//     recovery_id: i32) -> Result<Address, RecoveryError>{
//        return recover(message,signature,recovery_id);
// }







