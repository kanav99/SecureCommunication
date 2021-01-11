#[macro_use]
extern crate error_chain;

// use orion::aead;
mod helpers;
mod message;
mod user;

use helpers::errors::*;
use message::*;
use ring::aead;
use ring::{agreement, rand};
use user::User;

fn main() {
    if let Err(e) = real_main() {
        print_traceback(e);
    }
}

fn real_main() -> Result<()> {
    let mut alice = User::new("Alice", Variant::Orion);
    let mut bob = User::new("Bob", Variant::Orion);

    // Bob wants to send a message to Alice
    // let alice_key = alice.get_public_key();
    // let alice_var = alice.get_variant();
    // println!("{:?}", alice_key);
    bob.set_up_session(&mut alice);

    bob.send_message(&alice, "Hello Alice!");

    // let encrypted_session_key = bob.generate_session_key(alice_var, alice_key);
    // let secret_key = aead::SecretKey::default();
    // let ciphertext = aead::seal(&secret_key, "Secret message".as_bytes())?;
    // let decrypted_data = aead::open(&secret_key, &ciphertext)?;
    // assert_eq!("Secret message".as_bytes(), decrypted_data);

    Ok(())
}
