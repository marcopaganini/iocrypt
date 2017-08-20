# iocrypt

## I/O encryption/decryption library in Go.

This is a simple library that allows I/O streams to be easily encrypted and
decrypted using Go's standard AES/GCM implementation. Unlike the original
libraries, which operate on slices of bytes, iocrypt reads, encrypts, and saves
data in chunks, allowing the use of large data sets.

## SUPER IMPORTANT DISCLAIMER

**I'm NOT a cryptographer** and I've put together this in an afternoon. It uses
the standard libraries to encrypt/decrypt a file in "chunks", so it should be
safe. Use at your own risk. Feel free to review the code and report any
problems.

