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

    bob.send_message(&mut alice, "Hello Alice!")?;
    println!("{:?}", alice.get_last_message());
    alice.send_message(&mut bob, "Great, how about you?")?;
    println!("{:?}", bob.get_last_message());
    Ok(())
}

#[test]
fn consistency() -> Result<()> {
    let mut alice = User::new("Alice", Variant::OrionReversed)?;
    let mut bob = User::new("Bob", Variant::Orion)?;

    bob.set_up_session(&mut alice)?;
    bob.send_message(&mut alice, "Hello Alice!")?;
    assert_eq!(alice.get_last_message(), "Hello Alice!");

    alice.send_message(&mut bob, "Great, how about you?")?;
    assert_eq!(bob.get_last_message(), "Great, how about you?");

    Ok(())
}

#[test]
fn tampering() -> Result<()> {
    let mut alice = User::new("alice", Variant::Orion)?;
    let mut bob = User::new("bob", Variant::Orion)?;

    // Alice sets up session with bob
    alice.set_up_session(&mut bob)?;
    // Sends encrypted message in public domain
    let message = alice.form_message("Hello Bob!")?;

    let val = message.get_val();
    let mut tampered_val: Vec<u8> = Vec::new();
    for i in val {
        tampered_val.push(*i)
    }
    // Oscar tampers the message
    tampered_val[0] = 255 - tampered_val[0];
    let tampered_message = Message::new(tampered_val, message.get_sign());
    if let Ok(()) = bob.recv_message(&alice, tampered_message) {
        panic!("Bob recieved the tampered message");
    }
    Ok(())
}

#[test]
fn identity() -> Result<()> {
    let mut oscar = User::new("oscar", Variant::Orion)?;
    let alice = User::new("alice", Variant::Orion)?;
    let mut bob = User::new("bob", Variant::Orion)?;

    // Oscar sets up session with bob
    oscar.set_up_session(&mut bob)?;
    // Sends encrypted message in public domain
    let message = oscar.form_message("Hello Bob I am Alice!")?;

    // Bob tries to send the message using alice's identity
    if let Ok(()) = bob.recv_message(&alice, message) {
        panic!("Bob recieved the message with wrong identity");
    }
    Ok(())
}
