# __RSA encryption implementation in C (WIP)__

At the moment each character is encrypted/decrypted individually and small keys are used.
This means that the output is in a predictable format and can be reversed given enough time and resources.
This is meant to be a lightweight and fast way to encrypt data. It should not be used where security is extremely important.

rsa.h can be used as a header only library. rsa.c is just a sample.

    rsa.c usage: rsa [e public key] | [d private key] | [g] | [s sizeof_stdin_buffer]

## __example usage:__

### __generate the keys with the `g` option__

```./rsa g```

### __enter the text to be encryped through stdin and use the `e`__

```echo "text" | ./rsa e 3233 17```

### __enter the encryped text through stdin to be decrypted and use the `d`__

```echo "884 1313 1542 884" | ./rsa d 3233 413```

### __the `s` option can be used to specify the max size of the input to avoid overflow or wasted space__
@NOTE make sure there are at least 2 extra bytes given to the size option

```echo "test" | ./rsa e 3233 413 s 10```
