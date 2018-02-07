version       = "0.1.0"
author        = "Emery Hemingway, MoonMoonDogo"
description   = "A vanity address generator for TurtleCoin."
license       = "MIT"

requires "nim >= 0.17.1"
requires "base58 >= 0.1.1"

srcDir = "src"
binDir = "out"
bin = @["turtle_vanitygen"]
skipDirs = @["tests"]

task tests, "Runs tests":
  exec "nim c -r tests/crypto_tests"
  exec "nim c -r tests/mnemonic_tests"
