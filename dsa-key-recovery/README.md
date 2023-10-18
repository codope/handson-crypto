## Digital Signature Algorithm (DSA) Key-Recovery from Nonce

Let’s recall DSA signature.

- There are public parameters (p, q, g), where `p` and `q` are large primes; `p−1` is a multiple of `q`
  and `g` is a group generator. Also, `H(·)` is a cryptographic hash function.
- Key generation `KeyGen` generates secret key x ← Z<sub>q</sub><sup>*</sup>, and public key y ← g<sup>x</sup> mod p,
  and outputs (x, y).

- Signing algorithm `Sign(m)`:
    - generate a random nonce k ← Z<sub>q</sub><sup>*</sup>
    - r ← (g<sup>k</sup> mod p) mod q
    - s ← (k<sup>-1</sup>(H(m) + xr)) mod q
    - output pair (r, s).

_What is the vulnerability?_

It is possible that the range over which the random noncekis selected is very small. If an
attacker wants to retrieve the private key from the given signature (r, s) and the messagem, he
can exploit the fact that noncekis generated over a small range.

_How does the attack work?_

The attacker has access to the message `m` and `(r, s)` pair. He can first try to recover _k_ by
brute-force the range of _k_ (assuming it is small). Then use _k_ to recover the secret key _x_ from _s_.

## Task

Assume instead of using the large set Z<sub>q</sub><sup>*</sup>, the nonce _k_ is selected randomly from a small set
{ 1 , 2 ,... , 2<sup>16</sup> − 1 }. You are provided with a `input.json` file containing:

- Public parameters: (p, q, g), where `|q|= 160`, `|p|= 1024`; for simplicity we instantiate `H(·)`
  with `SHA-1`.
- Public key _y := g<sup>x</sup> mod p_
- Message _m_ and its signature pair `(r, s)` signed with _x_ and _k_
- Hash `h = SHA-1(m)` in hexadecimal representation

You are expected to compute k and produce the private key x that was used to sign the
message m.
