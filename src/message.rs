#[derive(Debug)]
pub enum Variant {
    Orion,
    Ring,
}

#[derive(Debug)]
pub struct Message {
    message: String,
    variant: Variant,
}
