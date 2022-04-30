# scala-cli-bazel-crypto-aes-encrypted-scrypt-encoded

## Description
Encrypt and decrypt password with AES
encoded scrypt.

When storing a password it is best practice
to use a one-way hash such as bcrypt, scrypt,
or argon2.

## Tech stack
- scala
- bazel
  - aes
  - scrypt

## Docker stack
- l.gcr.io/google/bazel

## To run
`sudo ./install.sh -u`

## To stop (optional)
`sudo ./install.sh -d`

## For help
`sudo ./install.sh -h`
