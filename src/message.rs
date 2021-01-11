#[derive(Debug)]
pub enum Variant {
    Orion,
    OrionReversed,
    // Ring, // I don't understand how to use Ring to perform AEAD
}

#[derive(Debug)]
pub struct Message {
    message: String,
    variant: Variant,
}
