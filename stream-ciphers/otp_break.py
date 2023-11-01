# Given that the one-time pad encryption of "attack at dawn" is provided, and assuming the same OTP key was used,
# we can determine the OTP key by XORing the plaintext message with the given ciphertext.
# Once we have the OTP key, we can then use it to XOR with the new message "attack at dusk" to get its encrypted form.
#
# Here's how to do this:
#
# 1. Convert the plaintext "attack at dawn" to its hexadecimal representation.
# 2. XOR this with the given ciphertext to get the OTP key.
# 3. Convert the plaintext "attack at dusk" to its hexadecimal representation.
# 4. XOR this with the OTP key to get the new ciphertext.


def string_to_hex(s):
    """Convert a string to its hexadecimal representation."""
    return ''.join('{:02x}'.format(ord(c)) for c in s)


def xor_hex(hex1, hex2):
    """XOR two hexadecimal strings."""
    return ''.join('{:02x}'.format(int(hex1[i:i + 2], 16) ^ int(hex2[i:i + 2], 16)) for i in range(0, len(hex1), 2))


def main():
    # Given data
    plaintext1 = "attack at dawn"
    ciphertext1 = "09e1c5f70a65ac519458e7e53f36"

    # Determine the OTP key by XORing plaintext1 and ciphertext1
    otp_key = xor_hex(string_to_hex(plaintext1), ciphertext1)

    # Encrypt "attack at dusk" using the OTP key
    plaintext2 = "attack at dusk"
    ciphertext2 = xor_hex(string_to_hex(plaintext2), otp_key)

    print("Encrypted message (attack at dusk):", ciphertext2)


if __name__ == "__main__":
    main()
