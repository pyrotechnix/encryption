# Simple encryption program
## Usage
To encrypt a file, use the command `./a.out input.

## Flags
- `-o output` : Set the filename of the output to output (defaults to output_ + input filename)
- `-p` : The program will ask you for a password and apply SHA256 to it to generate a key.
- `-k key` : Specify a key (formatted as a hex-string)
- `-n nonce` : Specify a nonce (formatted as a hex-string)
- `-w` : Writes a keyfile
- `-f keyfile` : Reads a keyfile at filename keyfile

## Misc
You can generate random keys here: https://randomkeygen.com/encryption-key. If unspecified, the program will use 0 as the key and nonce.
