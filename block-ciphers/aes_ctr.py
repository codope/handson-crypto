import os
from typing import List
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def xor_bytes(byte_seq1: bytes, byte_seq2: bytes) -> bytes:
    """Perform XOR operation between two byte sequences."""
    return bytes(x ^ y for x, y in zip(byte_seq1, byte_seq2))


def hex_string_to_blocks(hex_string: str, block_size: int = 16) -> List[bytes]:
    """Convert a hex string into a list of byte blocks."""
    byte_seq = bytes.fromhex(hex_string)
    return [byte_seq[i:i + block_size] for i in range(0, len(byte_seq), block_size)]


def decode_and_unpad_bytes(byte_blocks: List[bytes], block_size: int = 128, unpad: bool = False) -> str:
    """Convert a list of byte blocks into a string with optional padding removal."""
    combined_bytes = b''.join(byte_blocks)
    if unpad:
        unpadder = padding.PKCS7(block_size).unpadder()
        combined_bytes = unpadder.update(combined_bytes) + unpadder.finalize()
    return combined_bytes.decode('ascii')


def aes_ecb_operation(key: bytes, block: bytes, decrypt: bool = False) -> bytes:
    """Encrypt or decrypt a block of bytes using AES in ECB mode."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    operation = cipher.decryptor() if decrypt else cipher.encryptor()
    return operation.update(block) + operation.finalize()


def aes_cbc_decrypt(key: bytes, ciphertext: str) -> str:
    """Decrypt ciphertext using AES in CBC mode."""
    cipher_blocks = hex_string_to_blocks(ciphertext)
    plaintext_blocks = []
    previous_block = os.urandom(16)  # Dummy IV for the first block

    for i in range(1, len(cipher_blocks)):
        decrypted_block = aes_ecb_operation(key, cipher_blocks[i], decrypt=True)
        plaintext_blocks.append(xor_bytes(decrypted_block, cipher_blocks[i - 1]))
        previous_block = cipher_blocks[i]

    return decode_and_unpad_bytes(plaintext_blocks, unpad=True)


def aes_ctr_decrypt(key: bytes, ciphertext: str) -> str:
    """Decrypt ciphertext using AES in CTR mode."""
    cipher_blocks = hex_string_to_blocks(ciphertext)
    initial_counter = int.from_bytes(cipher_blocks[0], "big")
    plaintext_blocks = []

    for i, block in enumerate(cipher_blocks[1:]):
        counter_block = (initial_counter + i).to_bytes(16, byteorder="big")
        plaintext_blocks.append(xor_bytes(block, aes_ecb_operation(key, counter_block)))

    return decode_and_unpad_bytes(plaintext_blocks, unpad=False)


def main() -> None:
    """Main function demonstrating decryption of hardcoded ciphertexts."""
    cbc_key = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
    ctr_key = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")

    # CBC ciphertexts
    cbc_ciphertexts = [
        "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81",
        "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    ]

    # CTR ciphertexts
    ctr_ciphertexts = [
        "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329",
        "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    ]

    # Decryption demonstration
    for idx, cbc_ct in enumerate(cbc_ciphertexts, start=1):
        print(f"cbc {idx}:", aes_cbc_decrypt(cbc_key, cbc_ct))

    for idx, ctr_ct in enumerate(ctr_ciphertexts, start=1):
        print(f"ctr {idx}:", aes_ctr_decrypt(ctr_key, ctr_ct))


if __name__ == "__main__":
    main()
