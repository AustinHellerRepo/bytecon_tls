# bytecon_tls
This library contains client/server structs for sending and receiving messages that utilize the `bytecon` crate.

## Features
- Convenient sending and receiving of messages over TLS
- An implementation of `MessageProcessor` is used by the `ByteConServer` to process messages
- An enum `ByteConCertificate` for representing many different variations or ways of storing a certificate
  - It is also very easy to transition between different variants of this enum

## Usage
You will want to have shared request and response enums accessible to both your client and server. Please examine the unit tests for examples.