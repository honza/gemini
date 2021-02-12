# gemini client

A dumb gemini client in rust

## getting started

```
$ git clone https://github.com/honza/gemini
$ cd gemini
$ cargo build --release
$ ./target/release/gemini gemini://gemini.circumlunar.space/
```

Options:

```
gemini 0.2.0
A simple gemini client

USAGE:
    gemini [OPTIONS] <url>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --certificates <certificate-directory>     [default: certs]

ARGS:
    <url>
```

## license

GPLv3
