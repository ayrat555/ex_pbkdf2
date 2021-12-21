use core::convert::TryInto;
use pbkdf2::password_hash::Output;
use pbkdf2::password_hash::PasswordHash;
use pbkdf2::password_hash::PasswordHasher;
use pbkdf2::password_hash::PasswordVerifier;
use pbkdf2::password_hash::Salt;
use pbkdf2::password_hash::SaltString;
use pbkdf2::Algorithm;
use pbkdf2::Params;
use pbkdf2::Pbkdf2;
use rand_core::OsRng;

#[rustler::nif]
fn generate_salt() -> String {
    SaltString::generate(&mut OsRng).as_str().into()
}

#[rustler::nif]
fn calculate_pbkdf2(password: String, salt: String, alg: String, iterations: u32) -> String {
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

#[rustler::nif]
fn verify(hash: String, password: String, salt: String, alg: String, iterations: u32) -> bool {
    let algorithm = parse_alg(alg);
    let params = Params {
        rounds: iterations,
        output_length: 32,
    };
    let salt = Salt::new(&salt).unwrap();
    let password_hash = PasswordHash {
        algorithm: algorithm.ident(),
        version: None,
        hash: Some(Output::new(hash.as_bytes()).unwrap()),
        salt: Some(salt),
        params: params.try_into().unwrap(),
    };

    Pbkdf2
        .verify_password(password.as_bytes(), &password_hash)
        .is_ok()
}

fn parse_alg(alg: String) -> Algorithm {
    match alg.as_str() {
        "sha256" => Algorithm::Pbkdf2Sha256,
        "sha512" => Algorithm::Pbkdf2Sha512,
        &_ => panic!("Unknown hash alg!"),
    }
}

rustler::init!("Elixir.ExPBKDF2", [generate_salt, calculate_pbkdf2, verify]);
