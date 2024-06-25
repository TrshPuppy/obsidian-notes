
# Stream Cipher
Done one *byte* at a time. The first byte of data is taken and encrypted and stored, then the second byte is encrypted, then stored, and so on. This is *high speed* and low in *hardware complexity*.
### Challenges
With stream ciphers, you *don't know what data is coming later in the stream*, so it can be difficult to add randomization/ *entropy*. If multiple bytes *are identical* then there will be multiple identical bytes *in the encrypted output* as well. This is not cryptographically secure.
#### Initialization Vector (IV)
Added to the data stream to *introduce randomization*.
### Use
Stream Ciphers are often used w/ [symmetric encryption](symmetric-encryption.md) because it is low resource/ overhead.

> [!Resources]
> - [Professor Messer](https://www.youtube.com/watch?v=bEOrdqLB1Io&list=PLG49S3nxzAnkL2ulFS3132mOVKuzzBxA8&index=98)