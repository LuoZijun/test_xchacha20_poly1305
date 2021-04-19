#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;




#[derive(Clone)]
pub struct XChacha20 {
    inner: Chacha20,
}

impl XChacha20 {
    pub const KEY_LEN: usize   = Chacha20::KEY_LEN;
    pub const BLOCK_LEN: usize = Chacha20::BLOCK_LEN;
    pub const NONCE_LEN: usize = 24;


    pub fn new(key: &[u8]) -> Self {
        Self { inner: Chacha20::new(key) }
    }

    pub fn hchacha20(&self, nonce: &[u8]) -> (Chacha20, [u8; Chacha20::NONCE_LEN]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        unsafe {
            // HChaCha20
            let mut a = self.inner.a;
            let mut b = self.inner.b;
            let mut c = self.inner.c;

            // A 128-bit nonce ( 16 Bytes )
            let mut d = _mm256_broadcastsi128_si256(_mm_loadu_si128(nonce.as_ptr() as *const __m128i));

            // 20 rounds (diagonal rounds)
            diagonal_rounds(&mut a, &mut b, &mut c, &mut d);

            let mut chacha20_key = [0u8; Chacha20::KEY_LEN];
            let chacha20_key_mut_ptr = chacha20_key.as_mut_ptr() as *mut u32;

            // let a = _mm256_castsi256_si128(a);
            // let b = _mm256_castsi256_si128(b);
            // let c = _mm256_castsi256_si128(c);
            // let d = _mm256_castsi256_si128(d);

            _mm_storeu_si128(chacha20_key_mut_ptr.offset(0) as *mut __m128i, _mm256_castsi256_si128(a));
            _mm_storeu_si128(chacha20_key_mut_ptr.offset(4) as *mut __m128i, _mm256_castsi256_si128(d));

            // NOTE: SSE4.1
            // let k1 = _mm_extract_epi32(a, 0);
            // let k2 = _mm_extract_epi32(a, 1);
            // let k3 = _mm_extract_epi32(a, 2);
            // let k4 = _mm_extract_epi32(a, 3);

            let mut chacha20_nonce = [0u8; Chacha20::NONCE_LEN];
            chacha20_nonce[4..12].copy_from_slice(&nonce[16..24]);

            let chacha20 = Chacha20::new(&chacha20_key);
            // chacha20.in_place(init_block_counter, &chacha20_nonce, plaintext_or_ciphertext);
            (chacha20, chacha20_nonce)
        }
    }

    #[inline]
    unsafe fn in_place(&self, init_block_counter: u32, nonce: &[u8], plaintext_or_ciphertext: &mut [u8]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        // HChaCha20
        let mut a = self.inner.a;
        let mut b = self.inner.b;
        let mut c = self.inner.c;

        // A 128-bit nonce ( 16 Bytes )
        let mut d = _mm256_broadcastsi128_si256(_mm_loadu_si128(nonce.as_ptr() as *const __m128i));

        // 20 rounds (diagonal rounds)
        diagonal_rounds(&mut a, &mut b, &mut c, &mut d);

        let mut chacha20_key = [0u8; Chacha20::KEY_LEN];
        let chacha20_key_mut_ptr = chacha20_key.as_mut_ptr() as *mut u32;

        // let a = _mm256_castsi256_si128(a);
        // let b = _mm256_castsi256_si128(b);
        // let c = _mm256_castsi256_si128(c);
        // let d = _mm256_castsi256_si128(d);

        _mm_storeu_si128(chacha20_key_mut_ptr.offset(0) as *mut __m128i, _mm256_castsi256_si128(a));
        _mm_storeu_si128(chacha20_key_mut_ptr.offset(4) as *mut __m128i, _mm256_castsi256_si128(d));

        // NOTE: SSE4.1
        // let k1 = _mm_extract_epi32(a, 0);
        // let k2 = _mm_extract_epi32(a, 1);
        // let k3 = _mm_extract_epi32(a, 2);
        // let k4 = _mm_extract_epi32(a, 3);

        let mut chacha20_nonce = [0u8; Chacha20::NONCE_LEN];
        chacha20_nonce[4..12].copy_from_slice(&nonce[16..24]);

        let chacha20 = Chacha20::new(&chacha20_key);
        chacha20.in_place(init_block_counter, &chacha20_nonce, plaintext_or_ciphertext);
    }

    #[inline]
    pub fn encrypt_slice(&self, init_block_counter: u32, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        unsafe {
            self.in_place(init_block_counter, nonce, plaintext_in_ciphertext_out)
        }
    }

    #[inline]
    pub fn decrypt_slice(&self, init_block_counter: u32, nonce: &[u8], ciphertext_in_plaintext_and: &mut [u8]) {
        unsafe {
            self.in_place(init_block_counter, nonce, ciphertext_in_plaintext_and)
        }
    }
}

#[derive(Clone)]
pub struct Chacha20 {
    // initial_state: [u32; 16],
    a: __m256i,
    b: __m256i,
    c: __m256i,
}

impl Chacha20 {
    pub const KEY_LEN: usize   = 32;
    pub const BLOCK_LEN: usize = 64;
    pub const NONCE_LEN: usize = 12;

    // sigma constant b"expand 32-byte k" in little-endian encoding
    const K32: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        // let mut a = _mm256_broadcastsi128_si256(_mm_loadu_si128(state.as_ptr().offset( 0) as *const __m128i));
        // let mut b = _mm256_broadcastsi128_si256(_mm_loadu_si128(state.as_ptr().offset( 4) as *const __m128i));
        // let mut c = _mm256_broadcastsi128_si256(_mm_loadu_si128(state.as_ptr().offset( 8) as *const __m128i));
        // let mut d = _mm256_broadcastsi128_si256(_mm_loadu_si128(state.as_ptr().offset(12) as *const __m128i));

        let key_ptr = key.as_ptr() as *const u32;

        unsafe {
            // The ChaCha20 state is initialized as follows:
            let a = _mm256_broadcastsi128_si256(_mm_loadu_si128(Self::K32.as_ptr() as *const __m128i));

            // A 256-bit key (32 Bytes)
            let b = _mm256_broadcastsi128_si256(_mm_loadu_si128(key_ptr.offset(0) as *const __m128i));
            let c = _mm256_broadcastsi128_si256(_mm_loadu_si128(key_ptr.offset(4) as *const __m128i));

            Self { a, b, c }
        }
    }

    #[inline]
    unsafe fn in_place(&self, init_block_counter: u32, nonce: &[u8], plaintext_or_ciphertext: &mut [u8]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let nonce_ptr = nonce.as_ptr() as *const u32;

        let block_counter = init_block_counter;
        let n1 = *(nonce_ptr.offset(0));
        let n2 = *(nonce_ptr.offset(1));
        let n3 = *(nonce_ptr.offset(2));

        // ChaCha20 Counter (32-bits, little-endian)
        // let mut d_orig = unsafe {
        //     // _mm256_set_epi32(0, 0, 0, init_block_counter as i32,  0, 0, 0, init_block_counter as i32)
        //     // _mm256_broadcastsi128_si256(_mm_set_epi32(0, 0, 0, init_block_counter as i32))

        //     // BLOCK_COUNTER ( 4 Bytes ) + NONCE ( 12 Bytes )
        //     let mut tmp = [0u8; 16];
        //     tmp[0.. 4].copy_from_slice(&init_block_counter.to_le_bytes());
        //     tmp[4..16].copy_from_slice(&nonce);
        //     _mm256_broadcastsi128_si256(_mm_loadu_si128(tmp.as_ptr() as *const __m128i))
        // };
        let one = _mm256_set_epi32(0, 0, 0, 1,  0, 0, 0, 1);

        let mut d_orig = _mm256_broadcastsi128_si256(_mm_set_epi32(n3 as _, n2 as _, n1 as _, block_counter as i32));

        for chunk in plaintext_or_ciphertext.chunks_mut(Self::BLOCK_LEN) {
            let mut a = self.a;
            let mut b = self.b;
            let mut c = self.c;
            let mut d = d_orig;

            // 20 rounds (diagonal rounds)
            diagonal_rounds(&mut a, &mut b, &mut c, &mut d);

            a = _mm256_add_epi32(a, self.a);
            b = _mm256_add_epi32(b, self.b);
            c = _mm256_add_epi32(c, self.c);
            d = _mm256_add_epi32(d, d_orig);

            // INCR BlockCounter
            // block_counter = block_counter.wrapping_add(1);
            // d_orig = unsafe {
            //     _mm256_broadcastsi128_si256(_mm_set_epi32(n3 as _, n2 as _, n1 as _, block_counter as i32))
            // };
            d_orig = _mm256_add_epi32(d_orig, one);


            if chunk.len() == Self::BLOCK_LEN {
                // let chunk_ptr = chunk.as_ptr() as *const u32;
                // let chunk_mut_ptr = chunk.as_mut_ptr() as *mut u32;
                // 
                // NOTE: SSE
                // let p0 = _mm_loadu_si128(chunk_ptr.offset( 0) as *const __m128i);
                // let p1 = _mm_loadu_si128(chunk_ptr.offset( 4) as *const __m128i);
                // let p2 = _mm_loadu_si128(chunk_ptr.offset( 8) as *const __m128i);
                // let p3 = _mm_loadu_si128(chunk_ptr.offset(12) as *const __m128i);
                // 
                // _mm_storeu_si128(chunk_mut_ptr.offset( 0) as *mut __m128i, _mm_xor_si128(_mm256_castsi256_si128(a), p0));
                // _mm_storeu_si128(chunk_mut_ptr.offset( 4) as *mut __m128i, _mm_xor_si128(_mm256_castsi256_si128(b), p1));
                // _mm_storeu_si128(chunk_mut_ptr.offset( 8) as *mut __m128i, _mm_xor_si128(_mm256_castsi256_si128(c), p2));
                // _mm_storeu_si128(chunk_mut_ptr.offset(12) as *mut __m128i, _mm_xor_si128(_mm256_castsi256_si128(d), p3));

                let chunk_ptr = chunk.as_ptr() as *const u64;
                let chunk_mut_ptr = chunk.as_mut_ptr() as *mut u64;

                // AVX2
                let p0 = _mm256_loadu_si256(chunk_ptr.offset(0) as *const __m256i);
                let p1 = _mm256_loadu_si256(chunk_ptr.offset(4) as *const __m256i);
                _mm256_storeu_si256(chunk_mut_ptr.offset(0) as *mut __m256i,
                    _mm256_xor_si256(_mm256_set_m128i(_mm256_castsi256_si128(b), _mm256_castsi256_si128(a)), p0)
                );
                _mm256_storeu_si256(chunk_mut_ptr.offset(4) as *mut __m256i,
                    _mm256_xor_si256(_mm256_set_m128i(_mm256_castsi256_si128(d), _mm256_castsi256_si128(c)), p1)
                );
            } else {
                let mut last_block = [0u8; Self::BLOCK_LEN];
                last_block[..chunk.len()].copy_from_slice(&chunk);


                let chunk_ptr = last_block.as_ptr() as *const u32;
                let chunk_mut_ptr = last_block.as_mut_ptr() as *mut u32;

                let p0 = _mm_loadu_si128(chunk_ptr.offset( 0) as *const __m128i);
                let p1 = _mm_loadu_si128(chunk_ptr.offset( 4) as *const __m128i);
                let p2 = _mm_loadu_si128(chunk_ptr.offset( 8) as *const __m128i);
                let p3 = _mm_loadu_si128(chunk_ptr.offset(12) as *const __m128i);
                
                _mm_storeu_si128(chunk_mut_ptr.offset( 0) as *mut __m128i, _mm_xor_si128(_mm256_castsi256_si128(a), p0));
                _mm_storeu_si128(chunk_mut_ptr.offset( 4) as *mut __m128i, _mm_xor_si128(_mm256_castsi256_si128(b), p1));
                _mm_storeu_si128(chunk_mut_ptr.offset( 8) as *mut __m128i, _mm_xor_si128(_mm256_castsi256_si128(c), p2));
                _mm_storeu_si128(chunk_mut_ptr.offset(12) as *mut __m128i, _mm_xor_si128(_mm256_castsi256_si128(d), p3));


                chunk.copy_from_slice(&last_block[..chunk.len()]);
            }
        }
    }

    /// Nonce (96-bits, little-endian)
    #[inline]
    pub fn encrypt_slice(&self, init_block_counter: u32, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        unsafe {
            self.in_place(init_block_counter, nonce, plaintext_in_ciphertext_out)
        }
    }

    /// Nonce (96-bits, little-endian)
    #[inline]
    pub fn decrypt_slice(&self, init_block_counter: u32, nonce: &[u8], ciphertext_in_plaintext_and: &mut [u8]) {
        unsafe {
            self.in_place(init_block_counter, nonce, ciphertext_in_plaintext_and)
        }
    }
}

#[inline]
unsafe fn rotate_left(x: __m256i, bits: u8) -> __m256i {
    match bits {
        7 => {
            _mm256_or_si256(_mm256_slli_epi32(x, 7), _mm256_srli_epi32(x, 25))
        },
        8 => {
            let mask = _mm256_set_epi8(
                14, 13, 12, 15, 10, 9, 8, 11, 
                 6,  5,  4,  7,  2, 1, 0,  3, 
                14, 13, 12, 15, 10, 9, 8, 11, 
                 6,  5,  4,  7,  2, 1, 0,  3,
            );
            _mm256_shuffle_epi8(x, mask)
        },
        12 => {
            _mm256_or_si256(_mm256_slli_epi32(x, 12), _mm256_srli_epi32(x, 20))
        },
        16 => {
            let mask = _mm256_set_epi8(
                13, 12, 15, 14, 9, 8, 11, 10, 
                 5,  4,  7,  6, 1, 0,  3,  2, 
                13, 12, 15, 14, 9, 8, 11, 10, 
                 5,  4,  7,  6, 1, 0,  3,  2,
            );
            _mm256_shuffle_epi8(x, mask)
        },
        _ => unreachable!(),
    }
}

#[inline(always)]
unsafe fn quarter_round(a: &mut __m256i, b: &mut __m256i, c: &mut __m256i, d: &mut __m256i) {
    *a = _mm256_add_epi32(*a, *b);
    *d = _mm256_xor_si256(*d, *a);
    *d = rotate_left(*d, 16);

    *c = _mm256_add_epi32(*c, *d);
    *b = _mm256_xor_si256(*b, *c);
    *b = rotate_left(*b, 12);

    *a = _mm256_add_epi32(*a, *b);
    *d = _mm256_xor_si256(*d, *a);
    *d = rotate_left(*d, 8);

    *c = _mm256_add_epi32(*c, *d);
    *b = _mm256_xor_si256(*b, *c);
    *b = rotate_left(*b, 7);


    // Shuffle rows
    *b = _mm256_shuffle_epi32(*b, 0b_00_11_10_01);
    *c = _mm256_shuffle_epi32(*c, 0b_01_00_11_10);
    *d = _mm256_shuffle_epi32(*d, 0b_10_01_00_11);


    *a = _mm256_add_epi32(*a, *b);
    *d = _mm256_xor_si256(*d, *a);
    *d = rotate_left(*d, 16);

    *c = _mm256_add_epi32(*c, *d);
    *b = _mm256_xor_si256(*b, *c);
    *b = rotate_left(*b, 12);

    *a = _mm256_add_epi32(*a, *b);
    *d = _mm256_xor_si256(*d, *a);
    *d = rotate_left(*d, 8);

    *c = _mm256_add_epi32(*c, *d);
    *b = _mm256_xor_si256(*b, *c);
    *b = rotate_left(*b, 7);


    // Unshuffle rows
    *b = _mm256_shuffle_epi32(*b, 0b_10_01_00_11);
    *c = _mm256_shuffle_epi32(*c, 0b_01_00_11_10);
    *d = _mm256_shuffle_epi32(*d, 0b_00_11_10_01);
}

#[inline]
fn diagonal_rounds(a: &mut __m256i, b: &mut __m256i, c: &mut __m256i, d: &mut __m256i) {
    unsafe {
        quarter_round(a, b, c, d);
        quarter_round(a, b, c, d);
        quarter_round(a, b, c, d);
        quarter_round(a, b, c, d);
        quarter_round(a, b, c, d);

        quarter_round(a, b, c, d);
        quarter_round(a, b, c, d);
        quarter_round(a, b, c, d);
        quarter_round(a, b, c, d);
        quarter_round(a, b, c, d);
    }
}


#[cfg(test)]
#[bench]
fn bench_chacha20(b: &mut test::Bencher) {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 
        0x00, 0x00, 0x00, 0x00
    ];

    let mut ciphertext = test::black_box([
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
    ]);
    
    let cipher = Chacha20::new(&key);
    
    b.bytes = Chacha20::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice(1, &nonce, &mut ciphertext);
    })
}

#[cfg(test)]
#[bench]
fn bench_xchacha20(b: &mut test::Bencher) {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 
    ];

    let mut ciphertext = test::black_box([
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
    ]);
    
    let cipher = XChacha20::new(&key);
    
    b.bytes = XChacha20::BLOCK_LEN as u64;
    b.iter(|| {
        cipher.encrypt_slice(1, &nonce, &mut ciphertext);
    })
}

#[test]
fn test_xchacha20() {
    // Example and Test Vectors for XChaCha20
    // https://github.com/bikeshedders/xchacha-rfc/blob/master/xchacha.md#example-and-test-vectors-for-xchacha20
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x58,
    ];

    let plaintext = b"The dhole (pronounced \"dole\") is also known as the Asiatic wild dog\
, red dog, and whistling dog. It is about the size of a German shepherd but looks more like a \
long-legged fox. This highly elusive and skilled jumper is classified with wolves, coyotes, \
jackals, and foxes in the taxonomic family Canidae.";
    
    let cipher = XChacha20::new(&key);
    let block_counter = 0u32;

    let mut ciphertext = plaintext.to_vec();
    cipher.encrypt_slice(block_counter, &nonce, &mut ciphertext);
    assert_eq!(&ciphertext, &[
        0x45, 0x59, 0xab, 0xba, 0x4e, 0x48, 0xc1, 0x61, 0x02, 0xe8, 0xbb, 0x2c, 0x05, 0xe6, 0x94, 0x7f,
        0x50, 0xa7, 0x86, 0xde, 0x16, 0x2f, 0x9b, 0x0b, 0x7e, 0x59, 0x2a, 0x9b, 0x53, 0xd0, 0xd4, 0xe9,
        0x8d, 0x8d, 0x64, 0x10, 0xd5, 0x40, 0xa1, 0xa6, 0x37, 0x5b, 0x26, 0xd8, 0x0d, 0xac, 0xe4, 0xfa,
        0xb5, 0x23, 0x84, 0xc7, 0x31, 0xac, 0xbf, 0x16, 0xa5, 0x92, 0x3c, 0x0c, 0x48, 0xd3, 0x57, 0x5d,
        0x4d, 0x0d, 0x2c, 0x67, 0x3b, 0x66, 0x6f, 0xaa, 0x73, 0x10, 0x61, 0x27, 0x77, 0x01, 0x09, 0x3a,
        0x6b, 0xf7, 0xa1, 0x58, 0xa8, 0x86, 0x42, 0x92, 0xa4, 0x1c, 0x48, 0xe3, 0xa9, 0xb4, 0xc0, 0xda,
        0xec, 0xe0, 0xf8, 0xd9, 0x8d, 0x0d, 0x7e, 0x05, 0xb3, 0x7a, 0x30, 0x7b, 0xbb, 0x66, 0x33, 0x31,
        0x64, 0xec, 0x9e, 0x1b, 0x24, 0xea, 0x0d, 0x6c, 0x3f, 0xfd, 0xdc, 0xec, 0x4f, 0x68, 0xe7, 0x44,
        0x30, 0x56, 0x19, 0x3a, 0x03, 0xc8, 0x10, 0xe1, 0x13, 0x44, 0xca, 0x06, 0xd8, 0xed, 0x8a, 0x2b,
        0xfb, 0x1e, 0x8d, 0x48, 0xcf, 0xa6, 0xbc, 0x0e, 0xb4, 0xe2, 0x46, 0x4b, 0x74, 0x81, 0x42, 0x40,
        0x7c, 0x9f, 0x43, 0x1a, 0xee, 0x76, 0x99, 0x60, 0xe1, 0x5b, 0xa8, 0xb9, 0x68, 0x90, 0x46, 0x6e,
        0xf2, 0x45, 0x75, 0x99, 0x85, 0x23, 0x85, 0xc6, 0x61, 0xf7, 0x52, 0xce, 0x20, 0xf9, 0xda, 0x0c,
        0x09, 0xab, 0x6b, 0x19, 0xdf, 0x74, 0xe7, 0x6a, 0x95, 0x96, 0x74, 0x46, 0xf8, 0xd0, 0xfd, 0x41,
        0x5e, 0x7b, 0xee, 0x2a, 0x12, 0xa1, 0x14, 0xc2, 0x0e, 0xb5, 0x29, 0x2a, 0xe7, 0xa3, 0x49, 0xae,
        0x57, 0x78, 0x20, 0xd5, 0x52, 0x0a, 0x1f, 0x3f, 0xb6, 0x2a, 0x17, 0xce, 0x6a, 0x7e, 0x68, 0xfa,
        0x7c, 0x79, 0x11, 0x1d, 0x88, 0x60, 0x92, 0x0b, 0xc0, 0x48, 0xef, 0x43, 0xfe, 0x84, 0x48, 0x6c,
        0xcb, 0x87, 0xc2, 0x5f, 0x0a, 0xe0, 0x45, 0xf0, 0xcc, 0xe1, 0xe7, 0x98, 0x9a, 0x9a, 0xa2, 0x20,
        0xa2, 0x8b, 0xdd, 0x48, 0x27, 0xe7, 0x51, 0xa2, 0x4a, 0x6d, 0x5c, 0x62, 0xd7, 0x90, 0xa6, 0x63,
        0x93, 0xb9, 0x31, 0x11, 0xc1, 0xa5, 0x5d, 0xd7, 0x42, 0x1a, 0x10, 0x18, 0x49, 0x74, 0xc7, 0xc5,
    ]);

    let mut cleartext = ciphertext.clone();
    cipher.decrypt_slice(block_counter, &nonce, &mut cleartext);
    assert_eq!(&cleartext, &plaintext);
}

#[test]
fn test_chacha20() {
    // 2.4.2.  Example and Test Vector for the ChaCha20 Cipher
    // https://tools.ietf.org/html/rfc8439#section-2.4.2
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 
        0x00, 0x00, 0x00, 0x00
    ];
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
    let mut ciphertext = plaintext.to_vec();

    let chacha20 = Chacha20::new(&key);
    chacha20.encrypt_slice(1, &nonce, &mut ciphertext);
    assert_eq!(&ciphertext[..], &[
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    ]);
}
