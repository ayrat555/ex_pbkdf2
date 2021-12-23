use pbkdf2::password_hash::PasswordHash;
use pbkdf2::password_hash::PasswordHasher;
use pbkdf2::password_hash::PasswordVerifier;
use pbkdf2::password_hash::Salt;
use pbkdf2::password_hash::SaltString;
use pbkdf2::Algorithm;
use pbkdf2::Params;
use pbkdf2::Pbkdf2;
use rand_core::OsRng;
use rustler::types::binary::OwnedBinary;

#[rustler::nif]
fn generate_salt(format: bool) -> OwnedBinary {
    let result = SaltString::generate(&mut OsRng);

    if format {
        let mut erl_bin: OwnedBinary = OwnedBinary::new(22).unwrap();
        erl_bin.as_mut_slice().copy_from_slice(&result.as_bytes());

        erl_bin
    } else {
        let mut buffer = [0u8; 16];

        result.b64_decode(&mut buffer).unwrap();

        let mut erl_bin: OwnedBinary = OwnedBinary::new(16).unwrap();
        erl_bin.as_mut_slice().copy_from_slice(&buffer);

        erl_bin
    }
}

#[rustler::nif]
fn calculate_pbkdf2(
    password: String,
    salt: String,
    alg: String,
    iterations: u32,
    length: usize,
    format: bool,
) -> OwnedBinary {
    let params = Params {
        rounds: iterations,
        output_length: length,
    };

    let alg_var = parse_alg(alg);
    let salt = Salt::new(&salt).unwrap();

    let result = Pbkdf2
        .hash_password_customized(
            password.as_bytes(),
            Some(alg_var.ident()),
            None,
            params,
            salt,
        )
        .unwrap();

    let hash = result.hash.unwrap();

    if format {
        let str_hash = hash.to_string();
        let mut erl_bin: OwnedBinary = OwnedBinary::new(str_hash.len()).unwrap();
        erl_bin.as_mut_slice().copy_from_slice(&str_hash.as_bytes());

        erl_bin
    } else {
        let mut erl_bin: OwnedBinary = OwnedBinary::new(length).unwrap();
        erl_bin.as_mut_slice().copy_from_slice(&hash.as_bytes());

        erl_bin
    }
}

#[rustler::nif]
fn verify(hash: String, password: String) -> bool {
    let parsed_hash = PasswordHash::new(&hash).unwrap();

    Pbkdf2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

fn parse_alg(alg: String) -> Algorithm {
    match alg.as_str() {
        "sha256" => Algorithm::Pbkdf2Sha256,
        "sha512" => Algorithm::Pbkdf2Sha512,
        &_ => panic!("Unknown hash alg!"),
    }
}

rustler::init!(
    "Elixir.ExPBKDF2.Impl",
    [generate_salt, calculate_pbkdf2, verify]
);
