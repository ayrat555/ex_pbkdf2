use pbkdf2::password_hash::PasswordHash;
use pbkdf2::password_hash::PasswordHasher;
use pbkdf2::password_hash::PasswordVerifier;
use pbkdf2::password_hash::SaltString;
use pbkdf2::Algorithm;
use pbkdf2::Params;
use pbkdf2::Pbkdf2;
use rand_core::OsRng;
use rustler::Binary;
use rustler::Env;
use rustler::NewBinary;

#[rustler::nif]
fn generate_salt<'a>(env: Env<'a>) -> Binary<'a> {
    let result = SaltString::generate(&mut OsRng);

    let mut buffer = [0u8; 16];
    result.decode_b64(&mut buffer).unwrap();

    let mut erl_bin = NewBinary::new(env, 16);
    erl_bin.as_mut_slice().copy_from_slice(&buffer);

    erl_bin.into()
}

#[rustler::nif]
fn calculate_pbkdf2<'a>(
    env: Env<'a>,
    password: Binary,
    salt: Binary,
    alg: String,
    iterations: u32,
    length: usize,
) -> Binary<'a> {
    let params = Params {
        rounds: iterations,
        output_length: length,
    };

    let alg_var = parse_alg(alg);
    let salt = SaltString::encode_b64(&salt.as_slice()).unwrap();

    let result = Pbkdf2
        .hash_password_customized(
            password.as_slice(),
            Some(alg_var.ident()),
            None,
            params,
            salt.as_salt(),
        )
        .unwrap();

    let hash = result.hash.unwrap();

    let mut erl_bin = NewBinary::new(env, length);
    erl_bin.as_mut_slice().copy_from_slice(&hash.as_bytes());

    erl_bin.into()
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

rustler::init!("Elixir.ExPBKDF2.Impl");
