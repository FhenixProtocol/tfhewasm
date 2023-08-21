use sha2::{Digest, Sha256};
use std::io::Cursor;

use tfhe::boolean::client_key::ClientKey;
use tfhe::boolean::parameters::PARAMETERS_ERROR_PROB_2_POW_MINUS_165;
use tfhe::boolean::prelude::BinaryBooleanGates;
use tfhe::boolean::server_key::ServerKey;

use bincode2 as bincode;

const BENCH_NAME: &str = "bench_cpu_sha256";

#[no_mangle]
pub extern "C" fn bench_hash() -> u32 {
    let mut hashed: Vec<u8> = BENCH_NAME.into();
    for _i in 1..50_000 {
        hashed = Sha256::digest(&hashed).to_vec()
    }

    hashed[0] as u32
}

#[no_mangle]
pub extern "C" fn fhe_setup() -> u32 {

    let cks = ClientKey::new(&PARAMETERS_ERROR_PROB_2_POW_MINUS_165);
    // let sks = ServerKey::new(&cks);
    let sks_raw = include_bytes!("../server_key.txt");
    let server_key: ServerKey = bincode::deserialize(sks_raw).unwrap();

    let left = false;
    let right = true;

    let ct_left = cks.encrypt(left);
    let ct_right = cks.encrypt(right);

    let start = std::time::Instant::now();

    let num_loops: usize = 1;

    for _ in 0..num_loops {
        let _ = server_key.and(&ct_left, &ct_right);
    }
    let elapsed = start.elapsed().as_millis() as f64;
    let mean: f64 = elapsed / num_loops as f64;

    return elapsed as u32;
    // let cks_raw = include_bytes!("../client_key.txt");
    //
    // let config = ConfigBuilder::all_disabled()
    //     .enable_custom_integers(PARAM_MESSAGE_2_CARRY_2_PBS_KS, None)
    //     .build();
    //
    // let (client_key, server_key) = generate_keys(config);

    // let client_key: ClientKey = bincode::deserialize(cks_raw).unwrap();

    // set_server_key(server_key);
    //
    // return 0u32

    // let as_binary = hex::decode(cks_hex).unwrap();
    // let mut serialized_data = Cursor::new(as_binary);
    // let client_key: ClientKey = bincode::deserialize_from(&mut serialized_data).unwrap();
    //
    //
    // let clear_a = 27u8;
    // let clear_b = 128u8;
    //
    // let a = FheUint8::encrypt(clear_a, &client_key);
    // let b = FheUint8::encrypt(clear_b, &client_key);
    //
    // let result = a + b;
    //
    // let decrypted_result: u8 = result.decrypt(&client_key);
    //
    // let clear_result = clear_a + clear_b;
    //
    // clear_result as u32
}


// #[no_mangle]
// pub extern "C" fn fhe_add() -> u32 {
//
// }
