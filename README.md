office-crypto
=============

An application that partially implements the decryption of office documents for the purposes of password recovery.

Context
-------

_Now, I know what you're thinking..._ That seems like a bad thing to do, doesn't it? I feel the need to justify the
existing of this library a wee bit. I found myself needing to open some office documents that I had password-protected
years ago, and have since forgotten the password. I wanted to open my documents but the MS Office interface did not
allow me to guess password fast enough to find the missing parts of the password I couldn't remember.

And so, I decided to figure out how to do some of the underlying crypto, just enough to validate whether the password
is correct or not since that would allow me to guess much faster. And thus, this tool was born!

I decided to share it with the world since:

- it was a fun bit of code to write
- it was a good first real endeavour into the wonderful land of rust
- it may well be useful to others in the future

So, enjoy, but please only use to recover your own passwords.

Oh, and please forgive my probably-unidiomatic rust. First time here. =)

Usage
-----

To actually use it, you'll want to build it in release mode so it will run faster:

    cargo build --release

Then:

    target/release/office-crypto --input file.docx  --password-file passes.txt

Where 'passes.txt' is the file you have created containing all the passwords you want to guess.


Thanks
------

Was greatly helped by [herumi/msoffice](https://github.com/herumi/msoffice) which helped fill in lots of implementation blanks.

License
-------

This project is licensed under the terms of the [MIT license](LICENSE.md)
