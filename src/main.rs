#![feature(test)]
extern crate rand;
extern crate libc;
extern crate libsodium_sys;
extern crate crypto2;
#[cfg(test)]
extern crate test;


pub mod sodium;
pub mod xchacha20_poly1305;

use self::xchacha20_poly1305::XChacha20Poly1305;


#[bench]
fn xchacha20_poly1305(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
    ];
    let aad = [0u8; 0];

    let cipher = XChacha20Poly1305::new(&key);

    b.bytes = XChacha20Poly1305::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
            0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
            0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
            0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
            0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
            // TAG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        cipher.encrypt_slice(&nonce, &aad, &mut ciphertext);
        ciphertext
    })
}



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

    println!("random key, aad, nonce ...");
    let mut key   = [0u8; XChacha20Poly1305::KEY_LEN];
    let mut aad   = [0u8; 16];
    let mut nonce = [0u8; XChacha20Poly1305::NONCE_LEN];
    random(&mut key);
    random(&mut aad);
    random(&mut nonce);

    let c1 = XChacha20Poly1305::new(&key);
    let c2 = sodium::XChacha20Poly1305::new(&key);

    println!("ss-crypto2 XChacha20Poly1305 encrypt 5GB slice ...");
    c1.encrypt_slice(&nonce, &aad, &mut m1);

    println!("    sodium XChacha20Poly1305 encrypt 5GB slice ...");
    c2.encrypt_slice(&nonce, &aad, &mut m2);

    // let h1 = crypto2::hash::sha256(&m1);
    // let h2 = crypto2::hash::sha256(&m2);

    let ret = &m1 == &m2;
    println!("\n\nC1 == C2 = {}", ret);

    println!("Hello, world!");
}
