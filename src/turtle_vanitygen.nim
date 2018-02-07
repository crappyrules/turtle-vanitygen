import address, mnemonics, pcg, base58.cryptonote, crypto
import strutils, threadpool, cpuInfo, locks

when defined(windows):
  import windows_urandom as os_urandom
when not defined(windows):
  import posix_urandom as os_urandom

const FinalMsg = """

Write the mnemonic seed on paper and keep it in a safe place.
The spend and view secret key have been written to file.
"""

var chan: Channel[SpendSecret]
open chan

proc found(key: SpendSecret) =
  let b56Addr = $key.address
  var view = key.viewSecret
  withSecret view:
    stdout.writeLine "\n", b56Addr
    let words = key.keyToWords
    stdout.writeLine "\n",
      words[0..7].join(" "), "\n",
      words[8..15].join(" "), "\n",
      words[16..23].join(" "), "\n",
      words[24]
    writeFile(b56Addr & ".view", $view & "\n")
    writeFile(b56Addr & ".spend", $key & "\n")
    stdout.writeLine FinalMsg

proc bruteforce(index, seed: uint64; prefix: string) =
  var
    b58 = newString(cryptonote.FullEncodedBlockSize)
    #b58 = newString(cryptonote.FullEncodedBlockSize)
    buf: array[36, uint8]
    key: SpendSecret
    pcg = Pcg32(state: seed, inc: index)
  buf[0] = NetworkTag[0]
  buf[1] = NetworkTag[1]
  buf[2] = NetworkTag[2]
  buf[3] = NetworkTag[3]
  while true:
    for i in countup(0, <key.len, sizeof(uint32)):
      var x = pcg.next
      copyMem(addr key[i], addr x, sizeof(uint32))
    key.reduce
    key.toPublicKey cast[var PublicKey](addr buf[4])
    cryptonote.encodeBlock(b58, 0, buf, 0, FullBlockSize)
    #cryptonote.encodeBlock(b58, 11, buf, FullBlockSize, FullBlockSize)
    if b58.continuesWith(prefix, 6):
      # The first two characters of the address will contain a subset
      # of the base58 alphabet, skip them rather than wait for patterns
      # that will never occur
      withSecret key:
        chan.send key
      break

when defined(genode):
  const promptMsg = "Enter desired TurtleCoin address prefix: "
  stdout.write promptMsg
  var
    prefix = newString(FullEncodedBlockSize-5) # that would take a long time
    off = 0
    #linePos = promptMsg.len
  block input:
    while off < (prefix.len-2):
      if stdin.readChars(prefix, off, 1) == 1:
        let c = prefix[off]
        if not cryptonote.Alphabet.contains(c):
          if c in NewLines:
            break input
          elif c == 0x08.char and off > 0:
            prefix[off+1] = ' '
            prefix[off+2] = 0x08.char
            discard stdout.writeChars(prefix, off, 3)
            dec off
            #dec linePos
        else:
          let n = stdout.writeChars(prefix, off, 1)
          off.inc n
          #linePos.inc n
  prefix.setLen off
  stdout.write ". bruteforcing"
else:
  import os
  let params = commandLineParams()
  if params.len != 1:
    stderr.writeLine "please supply a TurtleCoin address prefix"
    quit 1
  let prefix = params[0]
  for c in prefix.items:
    if not cryptonote.Alphabet.contains(c):
      stderr.writeLine "character '", c, "' not in base56 alphabet"
      quit 1
  stdout.writeLine "gathering entropy and bruteforcing '", prefix, "'..."

proc randInt(): uint64 =
  let rand_seq = os_urandom.urandom(8)
  var offset = 0
  result = (cast[uint64](rand_seq[offset]) shl 0) or
           (cast[uint64](rand_seq[offset+1]) shl 8) or
           (cast[uint64](rand_seq[offset+2]) shl 16) or
           (cast[uint64](rand_seq[offset+3]) shl 24) or
           (cast[uint64](rand_seq[offset+4]) shl 32) or
           (cast[uint64](rand_seq[offset+5]) shl 40) or
           (cast[uint64](rand_seq[offset+6]) shl 48) or
           (cast[uint64](rand_seq[offset+7]) shl 56)

for i in 1..countProcessors():
  spawn bruteforce(i.uint64, randInt(), prefix)
  when defined(genode):
    stdout.write "."
when defined(genode):
  stdout.write "\n"

var key = chan.recv()
withSecret key:
  found key

echo "all done"
