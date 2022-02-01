mod pkcs11_key;
use clap::{Arg, App};

use base64::{encode};

const PUB_KEY: &str = "rsa-pub";
const PRIV_KEY: &str = "rsa-priv";
const PIN: &str = "1111";

fn init() {
    let (ctx, sh) =pkcs11_key::reset_token(PIN).unwrap();
        let (pub_h, priv_h) = pkcs11_key::fixture_key_pair(
        &ctx,
        sh,
        PUB_KEY.into(),
        PRIV_KEY.into(),
        true,
        true,
        true,
    ).unwrap();
    println!("new key generated! rsa-pub: {}, rsa-priv:{}",pub_h, priv_h )
}

fn sign_verify() {
    let (ctx, sh) =pkcs11_key::fixture_token(PIN).unwrap();
    let data = "test".as_bytes();
    let signature = pkcs11_key::ctx_sign(&ctx, sh, PRIV_KEY, data);
    let b64 = base64::encode(&signature);
    println!("{}", b64 );
    pkcs11_key::ctx_verify(&ctx, sh, PUB_KEY, data, &signature).unwrap();
    println!("sign_verify success." )
}

fn main() {
    let matches = App::new("PKCS11 Tests")
    .version("0.1.0")
    .about("PKCS11 testing program")
    .arg(Arg::new("init")
             .short('i')
             .long("init")
             .takes_value(false)
             .help("init token"))
    .arg(Arg::new("verify")
             .short('v')
             .long("verify")
             .takes_value(false)
             .help("verify signature"))

    .get_matches();

    if matches.is_present("init") {
        init(); 
    } else if matches.is_present("verify") {
        sign_verify(); 
    } else {
        println!("no operation, use flags -i or -v." )
    }

}
