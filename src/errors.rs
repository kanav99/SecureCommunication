error_chain! {
    foreign_links {
        Crypto(::orion::errors::UnknownCryptoError);
        UTF8Error(::std::string::FromUtf8Error);
    }
}

pub fn print_traceback(e: Error) {
    println!("Traceback:");

    let mut i = 1;
    for e in e.iter().skip(1) {
        println!("[{}]: {}", i, e);
        i += 1;
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::from("Unspecified Crypto Error")
    }
}

impl From<ring::error::KeyRejected> for Error {
    fn from(_: ring::error::KeyRejected) -> Self {
        Error::from("KeyRejected Crypto Error")
    }
}
