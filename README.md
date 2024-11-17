# bytecon_tls
This library contains client/server structs for sending and receiving messages that utilize the `bytecon` crate.

## Features
- Convenient sending and receiving of messages over TLS
- An implementation of `MessageProcessor` is used by the `ByteConServer` to process messages

## Usage
You will want to have shared request and response enums accessible to both your client and server. Please examine the unit tests for examples.