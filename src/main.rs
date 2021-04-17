extern crate rand;
extern crate libc;
extern crate libsodium_sys;
extern crate crypto2;

pub mod sodium;
pub mod xchacha20_poly1305;

use self::xchacha20_poly1305::XChacha20Poly1305;
use crypto2::hash::sha256;


const FIVE_GB: usize = 5 * 1024 * 1024 * 1024 + XChacha20Poly1305::TAG_LEN;


fn alloc() -> Vec<u8> {
    let mut data = Vec::with_capacity(FIVE_GB);
    unsafe { data.set_len(FIVE_GB) };

    data
}

fn random(data: &mut [u8]) {
    let mut rng  = rand::thread_rng();
    rand::Rng::fill(&mut rng, data);
}


fn main() {
    println!("alloc 5GB data ...");

    let mut m1 = alloc();
    println!("random 5GB data ...");
    random(&mut m1);

    println!("clone 5GB data ...");
    let mut m2 = m1.clone();

    let mut key   = [0u8; XChacha20Poly1305::KEY_LEN];
    let mut aad   = [0u8; 16];
    let mut nonce = [0u8; XChacha20Poly1305::NONCE_LEN];
    random(&mut key);
    random(&mut aad);
    random(&mut nonce);

    let c1 = XChacha20Poly1305::new(&key);
    let c2 = sodium::XChacha20Poly1305::new(&key);

    println!("ss-crypto2 XChacha20Poly1305 enc ...");
    c1.encrypt_slice(&nonce, &aad, &mut m1);

    println!("    sodium XChacha20Poly1305 enc ...");
    c2.encrypt_slice(&nonce, &aad, &mut m2);

    // let h1 = sha256(&m1);
    // let h2 = sha256(&m2);

    let ret = &m1 == &m2;
    println!("\n\nC1 == C2 = {}", ret);

    println!("Hello, world!");
}
