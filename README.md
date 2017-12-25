# shannon 
[![Build Status](https://travis-ci.org/chatoooo/shannon.svg?branch=master)](https://travis-ci.org/chatoooo/shannon) [![Go Report Card](https://goreportcard.com/badge/github.com/chatoooo/shannon)](https://goreportcard.com/report/github.com/chatoooo/shannon)

Pure Go implementation of Shannon stream cipher. No-brainer port of [rust-shannon](https://github.com/plietar/rust-shannon).

Shannon cipher is used in Spotify Connect to encrypt communication between player and Spotify AP server. Shannon cipher
is variant of [Sober](https://en.wikipedia.org/wiki/SOBER) stream cipher.

## Example
Encryption
```go
import "github.com/chatoooo/shannon"
...
key := []byte{0x65, 0x87, 0xd8, 0x8f, 0x6c, 0x32, 0x9d, 0x8a, 0xe4, 0x6b}
message := []byte("My secret message")
cipher := shannon.New(key)
cipher.Encrypt(message)
// message contains ciphertext now
mac := make([]byte, 16)
cipher.Final(mac)
// mac contains MAC of the message
```

Decryption
```go
import "github.com/chatoooo/shannon"
...
key := []byte{0x65, 0x87, 0xd8, 0x8f, 0x6c, 0x32, 0x9d, 0x8a, 0xe4, 0x6b}
// message is encrypted
message := []byte{0x91, 0x9d, 0xa9, 0xb6, 0x29, 0xfc, 0x9c, 0xdd, 0x17, 0x8c, 0x15, 0x31, 0x9a, 0xae, 0xcc, 0x6e, 0xd4}
receivedMac := []byte{0xbe, 0x7b, 0xef, 0x39, 0xee, 0xfe, 0x54, 0xfd, 0x8d, 0xb0, 0xbc, 0x6f, 0xd5, 0x30, 0x35, 0x19}
cipher := shannon.New(key)
cipher.Decrypt(message)
// message contains plaintext now
mac := make([]byte, 16)
if cipher.CheckMac(mac) == nil {
	fmt.Println("MAC OK")
}
```