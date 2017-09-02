# iocrypt

[![Build Status](https://travis-ci.org/marcopaganini/iocrypt.svg?branch=master)](https://travis-ci.org/marcopaganini/iocrypt)
[![Go Report Card](https://goreportcard.com/badge/github.com/marcopaganini/iocrypt)](https://goreportcard.com/report/github.com/marcopaganini/iocrypt)
[![GoDoc](https://godoc.org/github.com/marcopaganini/iocrypt?status.svg)](https://godoc.org/github.com/marcopaganini/iocrypt)

## I/O encryption/decryption library in Go.

This is a simple library that allows I/O streams to be easily encrypted and
decrypted using Go's standard AES/GCM implementation. Unlike the original
libraries, which operate on slices of bytes, iocrypt reads, encrypts, and saves
data in chunks, allowing the use of large data sets.

## SUPER IMPORTANT DISCLAIMER

**I am NOT a cryptographer** and I wrote this code in one afternoon. This library
makes use of the the standard libraries to encrypt/decrypt a file in "chunks",
so it _should_ be safe. Use at your own risk. Feel free to review the code and report any
problems.

