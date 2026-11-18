#!/usr/bin/env python3
"""Generate the gf_irreducible[] table of gf_irreducible.h (copy & paste the output).

Background: the fields GF(2^n) are built from an "irreducible polynomial" of degree n, i.e. a
polynomial with 0/1 coefficients that cannot be written as a product of smaller such polynomials
(like a prime number cannot be split into smaller factors). Polynomials with few terms make the
field arithmetic fast, so for every n we pick the "sparsest" one:
  1. a trinomial   x^n + x^k + 1                (3 terms), smallest k first, otherwise
  2. a pentanomial x^n + x^c + x^b + x^a + 1    (5 terms), in order of (c, b, a).
It is stored as {k, 0, 0} or {a, b, c}.

Usage: python gen_gf_irreducible.py [max_degree]     (default 1024, takes a few minutes)
"""
import sys

MAX_DEGREE = int(sys.argv[1]) if len(sys.argv) > 1 else 1024

# --- Polynomials as integers -------------------------------------------------------------------
# A polynomial with 0/1 coefficients is stored as an integer: bit i is the coefficient of x^i.
# Example: x^3 + x + 1  is  0b1011. Adding two polynomials is XOR (1 + 1 = 0 for these coefficients).
X = 0b10  # the polynomial "x"


def degree(poly):
    return poly.bit_length() - 1


def poly_mod(poly, modulus):
    """Remainder of `poly` divided by `modulus` (schoolbook long division, with XOR)."""
    while degree(poly) >= degree(modulus):
        poly ^= modulus << (degree(poly) - degree(modulus))
    return poly


def poly_gcd(a, b):
    """Greatest common divisor of two polynomials (Euclid's algorithm, as for integers)."""
    while b:
        a, b = b, poly_mod(a, b)
    return a


def poly_square(poly):
    """Square a polynomial. With 0/1 coefficients the cross terms cancel, so squaring just moves
    every term x^i to x^(2i), i.e. it inserts a zero bit between all bits of the integer.
    (Reading the binary digits as base-4 digits does exactly this.)"""
    return int(format(poly, "b"), 4)


# --- Irreducibility test (Ben-Or) --------------------------------------------------------------
def is_irreducible(f):
    """True if the polynomial f cannot be split into two smaller polynomials.

    Idea: the polynomial x^(2^i) - x is the product of all irreducible polynomials whose degree
    divides i (every element of GF(2^i) is a root of x^(2^i)-x). So if f has any factor of degree i (i <= degree(f) / 2), then the gcd of f and
    x^(2^i) - x is not 1. We try i = 1, 2, ... and give up as soon as a common factor shows up.
    If none shows up up to degree(f) / 2, f is irreducible (a reducible f always has a factor
    of at most half its degree).
    """
    x_pow = X  # will hold x^(2^i) mod f
    for _ in range(degree(f) // 2):
        x_pow = poly_mod(poly_square(x_pow), f)  # x^(2^(i-1)) -> x^(2^i), reduced mod f
        if poly_gcd(f, x_pow ^ X) != 1:          # "- x" is XOR as well
            return False
    return True


def make_poly(n, *middle_exponents):
    """x^n + x^e1 + x^e2 + ... + 1"""
    return (1 << n) | 1 | sum(1 << e for e in middle_exponents) # | is or like in C


def find_sparsest_irreducible(n):
    """Return the table entry {a, b, c} for degree n (see top of file)."""
    for k in range(1, n):
        if is_irreducible(make_poly(n, k)):
            print(n)
            return (k, 0, 0)
    for c in range(3, n):
        for b in range(2, c):
            for a in range(1, b):
                if is_irreducible(make_poly(n, c, b, a)):
                    print(n)
                    return (a, b, c)
    raise ValueError("no trinomial or pentanomial found for n = %d" % n)


# --- Output in the layout of gf_irreducible.h --------------------------------------------------
entries = ["{%d,%d,%d}," % find_sparsest_irreducible(n) for n in range(2, MAX_DEGREE + 1)]

# Break lines after at most 10 entries / 100 characters.
lines, line, count = [], "   ", 0
for entry in entries:
    if count == 10 or len(line) + 1 + len(entry) > 100:
        lines.append(line)
        line, count = "   ", 0
    line += " " + entry
    count += 1
lines.append(line)

print("\n".join(lines))
