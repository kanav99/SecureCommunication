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
        })
    }

    pub fn get_variant(&self) -> &Variant {
        return &self.variant;
    }

    pub fn get_public_key(&self) -> &[u8] {
        self.signing_key_pair.public_key().as_ref()
    }

    pub fn sign_message(&self, msg: &str) -> signature::Signature {
        self.signing_key_pair.sign(msg.as_bytes())
    }

    // JUST FOR DEBUG!!!
    // pub fn get_last_session_key(&self) -> [u8; 32] {
    //     self.last_session_key
    // }

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
                    self.last_session_key.copy_from_slice(_key_material);
                    Ok(())
                },
            )?;
            Ok(())
        })?;

        Ok(())
    }

    // pub fn msg_to_ciphertext(&self, peer: &User, msg: &str)

    pub fn send_message(&self, peer: &User, msg: &str) -> Result<()> {
        let peer_variant = peer.get_variant();
        println!("Leak from {:?}: {:?}", self.name, peer_variant);

        let sign = self.sign_message(msg);

        match peer_variant {
            Variant::Orion => {
                let sk = orion::aead::SecretKey::from_slice(&self.last_session_key)?;
                let ciphertext = orion::aead::seal(&sk, msg.as_bytes())?;
                println!("Leak from {:?}: {:?}", self.name, ciphertext);
                peer.recv_message(self, ciphertext, sign)?;
            }
            Variant::OrionReversed => {
                let sk = orion::aead::SecretKey::from_slice(&self.last_session_key)?;
                let ciphertext_r = orion::aead::seal(&sk, msg.as_bytes())?;
                let ciphertext = ciphertext_r.into_iter().rev().collect();
                println!("Leak from {:?}: {:?}", self.name, ciphertext);
                peer.recv_message(self, ciphertext, sign)?;
            }
        }
        Ok(())
    }

    pub fn recv_message(
        &self,
        peer: &User,
        ciphertext: Vec<u8>,
        sign: signature::Signature,
    ) -> Result<()> {
        let msg = match self.get_variant() {
            Variant::Orion => {
                let sk = orion::aead::SecretKey::from_slice(&self.last_session_key)?;
                orion::aead::open(&sk, &ciphertext)?
            }
            Variant::OrionReversed => {
                let sk = orion::aead::SecretKey::from_slice(&self.last_session_key)?;
                let ciphertext_r: Vec<_> = ciphertext.into_iter().rev().collect();
                orion::aead::open(&sk, &ciphertext_r)?
            }
        };

        let peer_public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, peer.get_public_key());

        peer_public_key.verify(&msg, sign.as_ref())?;
        println!(
            "Recieve {:?}: {:?} from {:?}",
            self.name,
            String::from_utf8(msg)?,
            peer.name
        );
        Ok(())
    }
}
