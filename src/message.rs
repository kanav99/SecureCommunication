use ring::signature;

#[derive(Debug)]
pub enum Variant {
    Orion,
    OrionReversed,
    // Ring, // I don't understand how to use Ring to perform AEAD
}

pub struct Message {
    val: Vec<u8>,
    sign: signature::Signature,
}

impl Message {
    pub fn new(val: Vec<u8>, sign: signature::Signature) -> Self {
        Message { val, sign }
    }

    pub fn get_val(&self) -> &Vec<u8> {
        &self.val
    }

    pub fn get_sign(&self) -> signature::Signature {
        self.sign
    }
}
