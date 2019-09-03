# Work in Progress

This repository contains Nim wrappers over a few of the cryptonote
cryptographic primitives and some address handling procedures.

These wrappers are used for a vanity address generator for [TurtleCoin](https://turtlecoin.lol/).
Most of this repository was programmed by @ehmry ([nim-monero](https://github.com/ehmry/nim-monero)).

## Dependencies

You'll need both `nim` and `nimble` installed. On ubuntu:

```sudo apt install nim```

## Building

Clone the repository and run ``nimble build`` inside of the directory.

## Running

Run the binary in the ``out`` directory with your desired prefix.

```
./turtle_vanitygen myprefix
```

## Limitations

Currently, only one block is encoded to base58 resulting in 12 characters.

TurtleCoin addresses start with ``TRTL``, followed by either ``u`` or ``v``,
followed by a subset of characters of the base58 alphabet followed by other
base58 characters. This means that the first 6 characters of a TurtleCoin
address are either fixed or limited to a subset of the base58 alphabet.
Therefore, it only makes sense to search for the prefix after the sixth
character. This also means that only prefixes up to six characters can be found.

If you want to search for a longer prefix, uncomment the lines below
```nim
#cryptonote.encodeBlock(b58, 11, buf, FullBlockSize, FullBlockSize)
#b58 = newString(cryptonote.FullEncodedBlockSize * 2)
```

and delete the following line
```nim
b58 = newString(cryptonote.FullEncodedBlockSize)
```

Be also aware that prefixes with 6 or more characters can take a very long time.
The time added per character grows exponentially.
