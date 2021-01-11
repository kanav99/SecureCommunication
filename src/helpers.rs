use orion;
use ring;

pub mod errors {
    error_chain! {
        foreign_links {
            Crypto(::orion::errors::UnknownCryptoError);
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
}
