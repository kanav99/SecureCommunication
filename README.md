# Secure Computation

* Struct `User` represents all the security parameters bound to a user. To initiate a session from user `a` to `b`, run `a.set_up_session(b)`. This stores the session key for encrypting messages in `a.session_key` and `b.session_key` (Private variables).

* To send a message from `a` to `b`, run `a.send_message(&mut b, "Hello B!")`. Or, first get the message struct `let message = a.form_message("Hello B!")?;` and then `b.recv_message(&a, message)`. This returns an error if the signature is invalid or the message gets tampered in between.

* MITM Hijacking possible in the session formation phase, due to limited time couldn't complete this part. The idea is described in the `mitm` test in `main.rs`.

* Tests for `tampering`, `identity`, and `consistency` have been added.
