import os
import string
from collections import defaultdict
from itertools import combinations
from typing import Dict, List, Tuple

# Many Time Pad
#
# Let us see what goes wrong when a stream cipher key is used more than once.
# Below are eleven hex-encoded ciphertexts that are the result of encrypting eleven plaintexts with a stream cipher,
# all with the same stream cipher key. Our goal is to decrypt the last ciphertext.
#
# Hint: XOR the ciphertexts together, and consider what happens when a space is XORed with a character in [a-zA-Z].

# Constants for encryption/decryption
CIPHERTEXTS_HEX = [
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba50",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb741",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de812",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee41",
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de812",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af513",
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e941",
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f404",
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d",
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
]

# Convert hex-encoded ciphertexts to bytes
CIPHERTEXTS = [bytes.fromhex(c) for c in CIPHERTEXTS_HEX]

# Potential characters to check in the xored result (a space and all ASCII letters)
POSSIBLE_CHARS = string.ascii_letters + " "


def strxor(a: bytes, b: bytes) -> bytes:
    """ XOR two bytes objects of possibly different lengths. """
    return bytes([x ^ y for (x, y) in zip(a, b)])


def random_bytes(size: int = 16) -> bytes:
    """ Generate random bytes using a secure random number generator. """
    return os.urandom(size)


def encrypt(key: bytes, msg: bytes) -> bytes:
    """ Encrypt a message using a key with XOR operation. """
    return strxor(key, msg)


def generate_ciphertexts(key: bytes, plaintexts: List[bytes]) -> List[bytes]:
    """ Encrypt a list of plaintext messages with the same key. """
    return [encrypt(key, msg) for msg in plaintexts]


def possible_xor_mappings(s: str) -> Dict[int, List[Tuple[int, int]]]:
    """ Generate a mapping of each byte value to all possible XOR'd ASCII character pairs. """
    charset = [ord(c) for c in s]
    mapping = defaultdict(list)
    for a, b in combinations(charset, r=2):
        mapping[a ^ b].append((a, b))
    mapping[0] = [(a, a) for a in charset]  # XORing a character with itself gives zero
    return mapping


def main():
    xor_mappings = possible_xor_mappings(POSSIBLE_CHARS)

    # Initialize a list of dictionaries to hold counts of possible key bytes
    possible_keys = [defaultdict(int) for _ in range(len(CIPHERTEXTS[0]))]

    # Iterate over all pairs of ciphertexts
    for c1, c2 in combinations(CIPHERTEXTS, r=2):
        for idx, (b1, b2) in enumerate(zip(c1, c2)):
            xored_byte = b1 ^ b2
            for (char1, char2) in xor_mappings[xored_byte]:
                possible_keys[idx][b1 ^ char1] += 1
                possible_keys[idx][b1 ^ char2] += 1

    # Guess the key byte that appears most frequently
    key_guess = [max(keys, key=keys.get) for keys in possible_keys]

    # Attempt to decrypt each ciphertext with the guessed key
    for i, cs in enumerate(CIPHERTEXTS):
        plaintext_guess = strxor(cs, key_guess)
        print(f"{i + 1:2} | {plaintext_guess.decode(errors='replace')}")


# Removed encryption logic as it's not needed for the decryption task

if __name__ == "__main__":
    main()
