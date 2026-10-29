#!/bin/sh
# Exercises every command of every demo_<code> program.
# usage: demo_smoke.sh BUILD_DIR
BUILD=${1:-.}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
failures=0

fail() { echo "  FAIL: $*"; failures=$((failures + 1)); }

# run NAME ARGS...: runs a demo in a fresh state dir A, output in $OUT
run() {
    code=$1; shift
    OUT=$("$BUILD/demo_$code" --dir "$WORK/$code" "$@" 2>&1)
    STATUS=$?
}

expect() { # expect "pattern" description
    echo "$OUT" | grep -q "$1" || fail "$2 (output: $OUT)"
}

ok() { [ "$STATUS" -eq 0 ] || fail "$* exited with $STATUS ($OUT)"; }

# check_code NAME REGULAR_KEYS ANAMORPHIC MESSAGE AMESSAGE SETUP...
check_code() {
    code=$1; regular=$2; ana=$3; msg=$4; amsg=$5; shift 5
    echo "demo_$code"

    run $code setup "$@"; ok "$code setup"
    [ -f "$WORK/$code/params.txt" ] || fail "$code: no params.txt"

    if [ "$regular" = 1 ]; then
        run $code keygen; ok "$code keygen"
        run $code export-key regular "$WORK/$code.reg"; ok "$code export regular"
        # a second state directory with the imported key must decode what the first encodes
        mkdir -p "$WORK/$code-b"
        cp "$WORK/$code/params.txt" "$WORK/$code-b/params.txt"
        OUT=$("$BUILD/demo_$code" --dir "$WORK/$code-b" import-key regular "$WORK/$code.reg" 2>&1); STATUS=$?
        ok "$code import regular"
    else
        run $code keygen; [ "$STATUS" -ne 0 ] || fail "$code: keygen must be refused (no regular key)"
    fi

    if [ "$ana" = 1 ]; then
        run $code akeygen; ok "$code akeygen"
        run $code export-key anamorphic "$WORK/$code.ana"; ok "$code export anamorphic"
        mkdir -p "$WORK/$code-b"
        cp "$WORK/$code/params.txt" "$WORK/$code-b/params.txt"
        OUT=$("$BUILD/demo_$code" --dir "$WORK/$code-b" import-key anamorphic "$WORK/$code.ana" 2>&1); STATUS=$?
        ok "$code import anamorphic"
    else
        run $code akeygen; [ "$STATUS" -ne 0 ] || fail "$code: akeygen must be refused"
    fi

    # regular encoding, decoded with the imported keys
    run $code encode "$msg" "$WORK/$code.ct"; ok "$code encode"
    OUT=$("$BUILD/demo_$code" --dir "$WORK/$code-b" decode "$WORK/$code.ct" 2>&1); STATUS=$?
    ok "$code decode"
    [ -z "$msg" ] || [ "$code" = 1a ] || expect "$msg" "$code: regular message not recovered"

    # a random string is not a codeword (zero-bit PRCs)
    if [ "$ana" = 1 ]; then
        run $code aencode "$amsg" "$msg" "$WORK/$code.act"; ok "$code aencode"
        OUT=$("$BUILD/demo_$code" --dir "$WORK/$code-b" adecode "$WORK/$code.act" 2>&1); STATUS=$?
        ok "$code adecode"
        [ -z "$amsg" ] || expect "$amsg" "$code: anamorphic message not recovered"
        # the anamorphic ciphertext is a valid regular ciphertext
        OUT=$("$BUILD/demo_$code" --dir "$WORK/$code-b" decode "$WORK/$code.act" 2>&1); STATUS=$?
        ok "$code decode of an anamorphic ciphertext"
        [ -z "$msg" ] || expect "$msg" "$code: regular message lost in anamorphic ciphertext"
        # regular ciphertexts carry no anamorphic message (not for the wiretap code: no authentication)
        # without indication seeds / authentication the decryption accepts every codeword
        if [ "${ROBUST:-1}" = 1 ]; then
            OUT=$("$BUILD/demo_$code" --dir "$WORK/$code-b" adecode "$WORK/$code.ct" 2>&1); STATUS=$?
            [ "$STATUS" -ne 0 ] || fail "$code: a regular ciphertext was accepted as anamorphic"
        fi
    else
        run $code aencode x y "$WORK/$code.act"; [ "$STATUS" -ne 0 ] || fail "$code: aencode must be refused"
    fi
}

# the smaller admissible LDPC instance (r = r' = 64, g = 4160) keeps the test fast
LDPC="n=16384 epsilon=6/7"

check_code ldpc    1 1 ""            ""               $LDPC
ROBUST=0
check_code pp      1 1 ""            "anamorphic-text"
check_code dc      1 0 ""            ""               slice_bits=15
check_code 1a      1 1 "1"           "1"              $LDPC
check_code low     1 1 "hello"       "10110"          $LDPC ell=40
check_code high    1 1 "hi-there"    "hide-me"        message_bits=64
check_code sharp   1 1 "ping"        "hide-me"
check_code cca     1 1 "ping"        "hide-me"
check_code wiretap 0 1 "regular text" "hidden text"
ROBUST=1
check_code rlnc    0 1 "regular text" "hidden text"

# with indication seeds (mu > 1) the decoder rejects regular ciphertexts again
check_code cca     1 1 "ping"        "hide-me"        indication_seeds=4

# hex messages ("hex:68656c6c6f" is "hello"); a malformed one is rejected
run rlnc encode "hex:68656c6c6f" "$WORK/hex.ct"; ok "rlnc encode of a hex message"
run rlnc decode "$WORK/hex.ct"; ok "rlnc decode of a hex message"
expect "message: hello" "hex message not recovered"
run rlnc encode "hex:6g" "$WORK/hex.ct"; [ "$STATUS" -ne 0 ] || fail "malformed hex message accepted"

# parameters that violate a requirement of the LDPC PRC are rejected
run ldpc setup n=1024 epsilon=3/4; [ "$STATUS" -ne 0 ] || fail "LDPC parameters with r <= 16 accepted"

# unknown parameters and malformed keys are rejected
run ldpc setup bogus=1; [ "$STATUS" -ne 0 ] || fail "unknown parameter accepted"
echo "not a key" > "$WORK/bad.key"
run ldpc import-key regular "$WORK/bad.key"; [ "$STATUS" -ne 0 ] || fail "malformed key accepted"

if [ "$failures" -ne 0 ]; then
    echo "$failures failure(s)"
    exit 1
fi
echo "all demos ok"
