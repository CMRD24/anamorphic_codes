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

Messages are plain strings, or `hex:` followed by hex digits for arbitrary
bytes (e.g. `hex:00ff10`); they are zero-padded to the size the code expects, and
a message that is too long is rejected. Decoded messages are printed as text
(trailing zeros removed), or as hex if they are not printable.

| Demo | Regular `MESSAGE` | Anamorphic `AMESSAGE` |
|---|---|---|
| `ldpc`, `pp`, `dc` | none (zero-bit: the codeword encodes the bit 1; the argument is ignored) | `ldpc`: none, `adecode` only reports whether an anamorphic message is present. `pp`: `amessage_bytes` bytes |
| `1a` | `0` or `1` | the bit string `1` (the only anamorphic message) |
| `low` | `ell/8` bytes | a bit string of at most `ell+1` characters `0`/`1` (one bit per block, padded with `0`), not all zero |
| `high` | `message_bits/8` bytes | `amessage_bytes` bytes |
| `sharp`, `cca` | `message_bits/8` bytes | `amessage_bytes` bytes |
| `rlnc` | one generation: `generation_size * payload_bytes` bytes | `(received_symbols-1) * (generation_size - a)` bytes with `a = ceil(lambda / log2 q)`; one GF(q) symbol per byte |
| `wiretap` | any length, padded to a multiple of `block_bytes` | `amessage_bytes` bytes |

For `1a` and `low` the anamorphic mode is the anamorphic lifting construction on
top of the anamorphic LDPC PRC: the ciphertext is a single codeword with `ell+1`
blocks (one for `1a`), and each block can hide one anamorphic bit, so the
anamorphic message is a bit string. `adecode` prints it with all `ell+1`
positions. They use the LDPC parameters of `demo_ldpc`.

`pp`, `high`, `sharp`, `cca` (and `demo_wiretap`) use randomness recovery: the
decoder recovers the seed of the encoding (`seed_bytes` bytes for `pp`,
`lambda/8` bytes for the others), and the anamorphic sender
puts the pseudorandom encryption `nonce || (PRF(key, nonce) xor message)` of the
anamorphic message there. The ciphertext fills the seed, so the nonce takes the
bytes the message leaves and must keep at least 8 bytes: with the defaults
(`amessage_bytes` 16 for a 24 byte seed, 8 for a 16 byte seed) the anamorphic
ciphertext is a single codeword (`mu = 1`), exactly as long as a regular one.
A longer message needs more seeds: `mu = indication_seeds + c`, where `c` is the
smallest number of seeds that hold nonce and message (`c = 1` as long as
`amessage_bytes <= seed bytes - 8`). `indication_seeds` adds that many extra
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
`adecode` the first `received_symbols` of them. You can delete or edit lines to simulate
a channel.

## Parameters

`setup` accepts `name=value`. Defaults:

| Demo | Parameters |
|---|---|
| `ldpc` | `n=65536 epsilon=3/4 delta=1/4 eta=0.005` |
| `dc` | `n=16384 epsilon=6/7 delta=1/4 eta=0.005 slice_bits=211` |
| `1a` | `n=65536 epsilon=3/4 delta=1/4 eta=0.005` |
| `low` | `n=65536 epsilon=3/4 delta=1/4 eta=0.005 ell=40` |
| `pp` | `n=384 q=2 symbol_bits=1 seed_bytes=24 delta=0 ecc=hamming indication_seeds=0 amessage_bytes=16` |
| `high` | `n=16384 epsilon=6/7 delta=1/4 eta=0.005 lambda=128 message_bits=64 indication_seeds=0 amessage_bytes=8` |
| `sharp`, `cca` | `n=16384 epsilon=6/7 delta=1/4 eta=0.005 lambda=128 message_bits=32 distance=0.05 indication_seeds=0 amessage_bytes=8` |
| `rlnc` | `q=256 payload_bytes=64 generation_size=16 lambda=64 received_symbols=20 sent_symbols=40` |
| `wiretap` | `block_bytes=32 lambda=128 amessage_bytes=16` |

Notes on the parameters:

- `n epsilon delta eta` define the LDPC PRC by the admissible choice of the
  thesis: `r = r' = ceil(n^(epsilon/2))` regular and anamorphic parity checks,
  `kappa = ceil(n^epsilon)`, `g = kappa + r'` generator columns, sparsity
  `t = floor(delta log2 n)` and encoder noise `eta` (a fraction such as `3/4` is
  accepted). `setup` rejects values that violate the requirements (R1)-(R6) of
  the thesis or give `r <= 16` (then the decoding threshold
  `(1/2 - r^(-1/4)) r` is not positive). The defaults have `n^epsilon = 2^12`,
  i.e. `r = r' = 64`, `kappa = 4096`, `g = 4160`; the codes whose codewords
  consist of many LDPC blocks (`dc`, `high`, `sharp`, `cca`) use `n = 2^14`,
  the others `n = 2^16`. Changing the parameters changes the keys, so run
  `keygen` again.
- The anamorphic LDPC mode is secure for `Q = kappa - log2(n)^2` anamorphic
  codewords per key (3840 with the defaults of `ldpc`).
- `distance` (`sharp`, `cca`) is the relative Hamming distance up to which the
  re-encoding check accepts; it must exceed the noise rate of the channel.
- For `pp` the recovered seed is the ECC input, so `n` must match
  `seed_bytes` (Hamming(7,4) doubles it: `n = 16 * seed_bytes` symbols of
  one bit). `amessage_bytes` is at most the seed length minus 8 bytes for a
  single codeword (see above).
- `rlnc` needs `generation_size >= 2a`, `received_symbols >= generation_size` and
  `sent_symbols >= received_symbols`. The defaults give only 64-bit security because the
  generation is small; use `lambda=128` with `q=16 generation_size=64` or
  larger for a 128-bit instance.
- `wiretap` needs `block_bytes` even and `block_bytes - amessage_bytes >= 16`.

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
  `indication_seeds=0`, returns output for ciphertexts that contain no anamorphic
  message: the encryption of the seed is not authenticated, so every ciphertext
  decodes to something (set `indication_seeds` for the PRCs to get rejection).
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

- Every round uses a fresh uniformly random regular and anamorphic message of
  the full length the code expects, sampled outside the measurement: random
  bytes for byte messages (for `rlnc` the whole generation, so every packet
  payload is random), a random bit for `1a`, a random nonzero bit string for the
  anamorphic message of `low`. `1a` has the single anamorphic message `1`, the
  zero-bit codes (`ldpc`, `pp` regular) have no message. With `mu > 1` the `mu`
  codewords of an anamorphic ciphertext carry the same regular message.
- Every key first runs one untimed warm-up round, so the samples are
  `K * N` per operation.
- Key generation is measured through the demo front end: the regular key
  generation is opening the code with the regular key; the anamorphic key is
  then generated on the same handle from its regular keys (they are generated
  only once per key). It is about zero for the randomness-recovery codes, whose
  anamorphic key is just random bytes. `rlnc` and `wiretap` are keyless and only
  have the anamorphic key.
- The randomness-recovery codes (`pp`, `high`, `sharp`, `cca`) use `mu = 1` by
  default, so an anamorphic ciphertext is as large as a regular one and the
  overhead is the encryption of the seed. Set `--param CODE:indication_seeds=N` or
  a longer `amessage_bytes` to benchmark `mu > 1`; the anamorphic operations
  then process `mu` times as much data and the ratio mostly reflects `mu`.
- The codes print their results while decoding; `bench` discards that output.
