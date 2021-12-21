use pbkdf2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, Salt, SaltString},
    Pbkdf2,
};

use pbkdf2::Algorithm;
use pbkdf2::Params;
use rand_core::OsRng;

#[rustler::nif]
fn add(a: i64, b: i64) -> i64 {
    a + b
}

#[rustler::nif]
fn generate_salt() -> String {
    SaltString::generate(&mut OsRng).as_str().into()
}

#[rustler::nif]
fn calc_pbkdf2(password: String, salt: String, alg: String, iterations: u32) -> String {
    let params = Params {
        rounds: iterations,
        output_length: 32,
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

    result.hash.unwrap().to_string()
}

// #[rustler::nif]
// fn verify(hash: String, password: String, salt: String, alg: String, iterations: u32) -> bool {

//     PasswordHash {
// }

fn parse_alg(alg: String) -> Algorithm {
    match alg.as_str() {
        "sha256" => Algorithm::Pbkdf2Sha256,
        "sha512" => Algorithm::Pbkdf2Sha512,
        &_ => panic!("Unknown hash alg!"),
    }
}

rustler::init!("Elixir.ExPBKDF2", [add, generate_salt, pbkdf2]);
