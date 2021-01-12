use crate::helpers::errors::*;
use crate::message::*;
use orion;
use ring::{
    agreement, rand,
    signature::{self, KeyPair},
};

#[derive(Debug)]
pub struct User {
    name: String,
    variant: Variant,
    last_session_key: [u8; 32],
    rng: rand::SystemRandom,
    signing_key_pair: signature::Ed25519KeyPair,
    last_message: String,
}

impl User {
    pub fn new(name: &str, variant: Variant) -> Result<User> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
        Ok(User {
            name: String::from(name),
            variant: variant,
            last_session_key: [0; 32],
            rng: rng,
            signing_key_pair: key_pair,
            last_message: String::new(),
        })
    }

    // Functions to get the public identity of a user
    pub fn get_variant(&self) -> &Variant {
        return &self.variant;
    }

    pub fn get_public_key(&self) -> signature::UnparsedPublicKey<&[u8]> {
        signature::UnparsedPublicKey::new(
            &signature::ED25519,
            self.signing_key_pair.public_key().as_ref(),
        )
    }

    // Only for test
    pub fn get_last_message(&self) -> &String {
        &self.last_message
    }

    // Session formation methods
    pub fn accept_session<F>(&mut self, peer_public_key: agreement::PublicKey, cb: F) -> Result<()>
    where
        F: FnOnce(bool, agreement::PublicKey) -> Result<()>,
    {
        let my_secret_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &self.rng)?;
        let my_public_key = my_secret_key.compute_public_key()?;

        println!("Leak From {:?}: {:?}", self.name, my_public_key);
        cb(true, my_public_key)?;

        agreement::agree_ephemeral(
            my_secret_key,
            &agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key),
            ring::error::Unspecified,
            |_key_material| {
                // Skipped KDF due to time limitations..
                self.last_session_key.copy_from_slice(_key_material);
                Ok(())
            },
        )?;

        Ok(())
    }

    pub fn set_up_session(&mut self, peer: &mut User) -> Result<()> {
        let my_secret_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &self.rng)?;
        let my_public_key = my_secret_key.compute_public_key()?;
        println!("Leak from {:?}: {:?}", self.name, my_public_key);
        peer.accept_session(my_public_key, |_accept, peer_public_key| {
            agreement::agree_ephemeral(
                my_secret_key,
                &agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key),
                ring::error::Unspecified,
                |_key_material| {
                    // Skipped KDF due to time limitations..
                    self.last_session_key.copy_from_slice(_key_material);
                    Ok(())
                },
            )?;
            Ok(())
        })?;

        Ok(())
    }

    // Encryption Methods
    pub fn encrypt_message(&self, variant: &Variant, msg: &str) -> Result<Vec<u8>> {
        let ct = match variant {
            Variant::Orion => {
                let sk = orion::aead::SecretKey::from_slice(&self.last_session_key)?;
                orion::aead::seal(&sk, msg.as_bytes())?
            }
            Variant::OrionReversed => {
                let sk = orion::aead::SecretKey::from_slice(&self.last_session_key)?;
                let ciphertext_r = orion::aead::seal(&sk, msg.as_bytes())?;
                ciphertext_r.into_iter().rev().collect()
            }
        };
        Ok(ct)
    }

    pub fn decrypt_message(&self, variant: &Variant, ciphertext: &Vec<u8>) -> Result<Vec<u8>> {
        let msg = match variant {
            Variant::Orion => {
                let sk = orion::aead::SecretKey::from_slice(&self.last_session_key)?;
                orion::aead::open(&sk, &ciphertext)?
            }
            Variant::OrionReversed => {
                let sk = orion::aead::SecretKey::from_slice(&self.last_session_key)?;
                let mut ciphertext_r: Vec<u8> = Vec::new();
                for i in ciphertext.iter().rev() {
                    ciphertext_r.push(*i);
                }
                orion::aead::open(&sk, &ciphertext_r)?
            }
        };
        Ok(msg)
    }

    pub fn sign_message(&self, msg: &str) -> signature::Signature {
        self.signing_key_pair.sign(msg.as_bytes())
    }

    pub fn form_message(&self, msg: &str) -> Result<Message> {
        let my_variant = self.get_variant();
        let sign = self.sign_message(msg);
        let ciphertext = self.encrypt_message(my_variant, msg)?;
        Ok(Message::new(ciphertext, sign))
    }

    pub fn send_message(&self, peer: &mut User, msg: &str) -> Result<()> {
        let message = self.form_message(msg)?;
        // Send message
        println!("Leak from {:?}: {:?}", self.name, message.get_val());
        peer.recv_message(self, message)?;
        Ok(())
    }

    pub fn recv_message(&mut self, peer: &User, message: Message) -> Result<()> {
        let ciphertext = message.get_val();
        let sign = message.get_sign();
        let peer_variant = peer.get_variant();
        let msg = self.decrypt_message(peer_variant, ciphertext)?;

        let peer_public_key = peer.get_public_key();
        peer_public_key.verify(&msg, sign.as_ref())?;

        self.last_message = String::from_utf8(msg)?;
        Ok(())
    }
}
