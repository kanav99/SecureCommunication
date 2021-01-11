#[macro_use]
extern crate error_chain;

// use orion::aead;
mod helpers;
mod message;
mod user;

use helpers::errors::*;
use message::*;
use user::User;

fn main() {
    if let Err(e) = real_main() {
        print_traceback(e);
    }
}

fn real_main() -> Result<()> {
    let mut alice = User::new("Alice", Variant::OrionReversed)?;
    let mut bob = User::new("Bob", Variant::Orion)?;

    // Bob wants to send a message to Alice
    bob.set_up_session(&mut alice)?;

    bob.send_message(&alice, "Hello Alice!")?;
    alice.send_message(&bob, "Great, how about you?")?;

    Ok(())
}
