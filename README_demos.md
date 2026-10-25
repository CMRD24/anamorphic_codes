# Demo programs

Every code in this repository has a command line demo, `demo_<code>`. All demos
share the same commands; only the parameters and the sizes of keys, messages and
codewords differ.

| Program | Code | Regular key | Anamorphic mode |
|---|---|---|---|
| `demo_ldpc` | LDPC zero-bit PRC | yes | native (second parity-check matrix) |
| `demo_pp` | permuted puzzle zero-bit PRC | yes | randomness recovery |
| `demo_dc` | deletion-channel zero-bit PRC (on LDPC) | yes | – |
| `demo_1a` | `PRC^1_adapt` (one bit) | yes | lifting of the LDPC anamorphic mode |
| `demo_low` | `PRC_low` (ell bits) | yes | lifting of the LDPC anamorphic mode |
| `demo_high` | `PRC_high` | yes | randomness recovery |
| `demo_sharp` | `PRC_sharp` | yes | randomness recovery |
| `demo_cca` | `PRC_cca` | yes | randomness recovery |
| `demo_rlnc` | RLNC | – (keyless) | Reed-Solomon points in the headers |
| `demo_wiretap` | wiretap code (OAEP4, Hamming(7,4)) | – (keyless) | randomness recovery |

## Build

Requires CMake, a C11 compiler, libsodium and M4RI (`libm4ri-dev` on Debian/Ubuntu, dense linear algebra over GF(2)). The wiretap demo also needs
OpenSSL (it is skipped if OpenSSL is not found).

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The programs are in `build/`. `ctest --test-dir build` runs the unit tests and a
smoke test (`tests/demo_smoke.sh`) that exercises every command of every demo.

## Commands

```
demo_<code> [--dir DIR] setup [name=value ...]
demo_<code> [--dir DIR] keygen
demo_<code> [--dir DIR] akeygen
demo_<code> [--dir DIR] export-key regular|anamorphic FILE
demo_<code> [--dir DIR] import-key regular|anamorphic FILE
demo_<code> [--dir DIR] encode  [MESSAGE] CIPHERTEXT
demo_<code> [--dir DIR] aencode AMESSAGE [MESSAGE] CIPHERTEXT
demo_<code> [--dir DIR] decode  CIPHERTEXT
demo_<code> [--dir DIR] adecode CIPHERTEXT
```

Running a demo without arguments prints the commands it supports and its
parameters with their defaults.

| Command | What it does |
|---|---|
| `setup` | Writes the regular and anamorphic parameters to `DIR/params.txt`. Parameters you do not give keep their current value (initially the default). The parameters are checked by building the code, so invalid values are rejected here. Prints the resulting parameters. |
| `keygen` | Generates the regular key (PRCs only). |
| `akeygen` | Generates the anamorphic key (not for `dc`). |
| `export-key` / `import-key` | Copy a key out of / into the state directory. Importing validates the file. |
| `encode` | Regular encoding. |
| `aencode` | Anamorphic encoding: hides `AMESSAGE` in a codeword that still carries `MESSAGE`. |
| `decode` | Regular decoding. Also works on anamorphic ciphertexts (the anamorphic mode preserves the regular one). |
| `adecode` | Anamorphic decoding. |

**State.** Each invocation is a separate process; parameters and keys persist in
`DIR` (default `./<code>_demo`): `params.txt`, `key.regular`, `key.anamorphic`.
`encode`/`decode` need the regular key (PRCs), `aencode`/`adecode` additionally
the anamorphic key. Two directories with the same parameters and imported keys
interoperate.

**Exit status.** 0 on success, 1 on failure or rejection (for example `decode`
of a string that is not a codeword), 2 on a usage error.

## Keys

- **PRCs.** A key file is a 32-byte seed in hex (64 digits). The key generation
  of the code is re-run from the seed with a deterministic generator, so the
  regular and the anamorphic key are each a single seed. The regular seed is
  the secret for both the encoding and the decoding key; there is no
  encoding-only export. The native LDPC anamorphic key is derived from the
  regular key as well, so `akeygen` can be run before or after `import-key`
  but both keys must be present when encoding or decoding.
- **`demo_rlnc`, `demo_wiretap`.** These codes are keyless. The anamorphic key is
  the 32-byte symmetric key itself.

## Messages and ciphertext files

Messages are plain strings, zero-padded to the size the code expects; a message
that is too long is rejected. Decoded messages are printed as text (trailing
zeros removed), or as hex if they are not printable.

| Demo | Regular `MESSAGE` | Anamorphic `AMESSAGE` |
|---|---|---|
| `ldpc`, `pp`, `dc` | none (zero-bit: the codeword encodes the bit 1; the argument is ignored) | `ldpc`: none, `adecode` only reports whether an anamorphic message is present. `pp`: `amessage_bytes` bytes |
| `1a` | `0` or `1` | the bit string `1` (the only anamorphic message) |
| `low` | `ell/8` bytes | a bit string of at most `ell+1` characters `0`/`1` (one bit per block, padded with `0`), not all zero |
| `high` | `message_bits/8` bytes | `amessage_bytes` bytes |
| `sharp`, `cca` | `message_bits/8` bytes | `amessage_bytes` bytes |
| `rlnc` | one generation: `generation_size * packet_size` bytes | `(received-1) * (generation_size - a)` bytes with `a = ceil(lambda / log2 q)`; one GF(q) symbol per byte |
| `wiretap` | any length, padded to a multiple of `K_bytes` | `ana_message_length` bytes |

For `1a` and `low` the anamorphic mode is the anamorphic lifting construction on
top of the anamorphic LDPC PRC: the ciphertext is a single codeword with `ell+1`
blocks (one for `1a`), and each block can hide one anamorphic bit, so the
anamorphic message is a bit string. `adecode` prints it with all `ell+1`
positions. They use the LDPC parameters of `demo_ldpc` (a large `g`).

`pp`, `high`, `sharp`, `cca` (and `demo_wiretap`) use randomness recovery: the
decoder recovers the seed of the encoding (`message_bytes` bytes for `pp`,
`lambda/8` or `lambda_bits/8` bytes for the others), and the anamorphic sender
puts the pseudorandom encryption `nonce || (PRF(key, nonce) xor message)` of the
anamorphic message there. The ciphertext fills the seed, so the nonce takes the
bytes the message leaves and must keep at least 8 bytes: with the defaults
(`amessage_bytes` 16 for a 24 byte seed, 8 for a 16 byte seed) the anamorphic
ciphertext is a single codeword (`mu = 1`), exactly as long as a regular one.
A longer message needs more seeds: `mu = indication_len + c`, where `c` is the
smallest number of seeds that hold nonce and message (`c = 1` as long as
`amessage_bytes <= seed bytes - 8`). `indication_len` adds that many extra
codewords whose seeds satisfy `PRF(seed) = 0`; they make `adecode` reject strings
that are not anamorphic. Without them (the default) the decryption is not
authenticated, so `adecode` returns some message for every codeword it can
read, regular ones included. For `high`, `sharp`, `cca` `aencode` takes the
regular messages of the `mu` codewords as `m1;m2;...`; the last one is repeated
if fewer are given.

A ciphertext file is text: the line `demo-ciphertext`, a line
`<count> <bits per codeword>`, and one hex line per codeword (bit `i` is bit
`i mod 8` of byte `i / 8`). For `rlnc` each codeword is one symbol (global
encoding vector, then payload); `decode` uses all symbols in the file and
`adecode` the first `received` of them. You can delete or edit lines to simulate
a channel.

## Parameters

`setup` accepts `name=value`. Defaults:

| Demo | Parameters |
|---|---|
| `ldpc` | `n=1024 r=256 g=512 t=10 eta=0.01` |
| `dc` | `n=128 r=64 g=32 t=4 eta=0.01 T=211` |
| `1a` | `n=1024 r=256 g=512 t=10 eta=0.01` |
| `low` | `n=1024 r=256 g=512 t=10 eta=0.01 ell=40` |
| `pp` | `n=384 q=2 symbol_bits=1 message_bytes=24 delta=0 ecc=hamming indication_len=0 amessage_bytes=16` |
| `high` | `n=1024 r=512 g=256 t=11 eta=0.01 lambda=128 message_bits=64 indication_len=0 amessage_bytes=8` |
| `sharp`, `cca` | `n=1024 r=512 g=256 t=11 eta=0.01 lambda_bits=128 message_bits=32 delta=0.05 indication_len=0 amessage_bytes=8` |
| `rlnc` | `q=256 packet_size=64 generation_size=16 lambda=64 received=20 sent=40` |
| `wiretap` | `K_bytes=32 security_parameter=128 ana_message_length=16` |

Notes on the parameters:

- `n r g t eta` are the LDPC parameters (block length, parity checks, generator
  columns, check sparsity, encoder noise). Changing them changes the keys, so
  run `keygen` again.
- `ldpc` anamorphism uses `g/2` extra parity checks, so `g` must be large
  enough for the decoding threshold: with a small `g` (for example 100 or 256
  at `n=1024`) anamorphic decoding fails regularly.
- For `pp` the recovered seed is the ECC input, so `n` must match
  `message_bytes` (Hamming(7,4) doubles it: `n = 16 * message_bytes` symbols of
  one bit). `amessage_bytes` is at most the seed length minus 8 bytes for a
  single codeword (see above).
- `rlnc` needs `generation_size >= 2a`, `received >= generation_size` and
  `sent >= received`. The defaults give only 64-bit security because the
  generation is small; use `lambda=128` with `q=16 generation_size=64` or
  larger for a 128-bit instance.
- `wiretap` needs `K_bytes` even and `K_bytes - ana_message_length >= 16`.

## Example

```sh
build/demo_cca --dir alice setup message_bits=32
build/demo_cca --dir alice keygen
build/demo_cca --dir alice akeygen
build/demo_cca --dir alice export-key regular   cca.regular
build/demo_cca --dir alice export-key anamorphic cca.ana

build/demo_cca --dir alice aencode "meet at dawn" "ping" msg.ct

# the receiver imports both keys (and uses the same parameters)
cp alice/params.txt bob/params.txt   # or run setup with the same values
build/demo_cca --dir bob import-key regular    cca.regular
build/demo_cca --dir bob import-key anamorphic cca.ana
build/demo_cca --dir bob adecode msg.ct   # anamorphic message: meet at dawn
build/demo_cca --dir bob decode  msg.ct   # codeword 0: ping ...
```

## Limitations

- `adecode` of `demo_wiretap`, and of `pp`, `high`, `sharp`, `cca` with the default
  `indication_len=0`, returns output for ciphertexts that contain no anamorphic
  message: the encryption of the seed is not authenticated, so every ciphertext
  decodes to something (set `indication_len` for the PRCs to get rejection).
  `demo_ldpc`, `demo_1a`, `demo_low` and `demo_rlnc` reject ciphertexts without
  an anamorphic message.
- The PRC demos do not model a channel; to test error correction, flip bits in
  the ciphertext file yourself.
- `dc` has no anamorphic mode.

## Benchmark

`bench` compares the anamorphic operations with the regular ones for every code
that has an anamorphic mode (`ldpc`, `pp`, `1a`, `low`, `high`, `sharp`, `cca`,
`rlnc`, and `wiretap` if OpenSSL is available). It uses the same code
configurations as the demos.

```sh
build/bench [--keys K] [--ops N] [--codes LIST] [--param CODE:NAME=VALUE]... [--csv FILE]
```

| Option | Meaning |
|---|---|
| `--keys K` | number of key generations per code, each with a fresh random key (default 3) |
| `--ops N` | rounds per key (default 10); a round is `encode`, `decode`, `aencode`, `adecode` |
| `--codes LIST` | comma separated codes, or `all` (default) |
| `--param CODE:NAME=VALUE` | override a demo parameter for one code, repeatable, e.g. `--param low:ell=16 --param rlnc:lambda=32` |
| `--csv FILE` | also write the results as CSV |

Per code it reports mean, standard deviation, minimum and number of samples (in
milliseconds) of key generation, `encode`, `aencode`, `decode`, `adecode`,
`encode + decode` and `aencode + adecode`, the anamorphic/regular ratio and
difference, and the size of the regular and anamorphic ciphertexts. Failed
operations (for example an `adecode` that does not recover the message) are
counted and shown next to the row.

Notes:

- Every key first runs one untimed warm-up round, so the samples are
  `K * N` per operation.
- Key generation is measured through the demo front end: the regular key
  generation is opening the code with the regular key, the anamorphic one is
  the additional time when the anamorphic key is present (reported as `+`; it
  is about zero for the randomness-recovery codes, whose anamorphic key is just
  random bytes). `rlnc` and `wiretap` are keyless and only have the anamorphic
  key.
- The randomness-recovery codes (`pp`, `high`, `sharp`, `cca`) use `mu = 1` by
  default, so an anamorphic ciphertext is as large as a regular one and the
  overhead is the encryption of the seed. Set `--param CODE:indication_len=N` or
  a longer `amessage_bytes` to benchmark `mu > 1`; the anamorphic operations
  then process `mu` times as much data and the ratio mostly reflects `mu`.
- The codes print their results while decoding; `bench` discards that output.
