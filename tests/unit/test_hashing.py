"""
Unit Tests for Streaming SHA-256 & SHA-512 Cryptographic Hashing Engine
Validates against standard NIST test vectors and custom chunk sizes.
"""

import io

from provenanceguard.core.common.crypto import calculate_stream_digests
from provenanceguard.core.domain.enums import DigestAlgorithm


def test_nist_empty_string_hashes():
    # Empty payload SHA-256 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    stream = io.BytesIO(b"")
    digests, total_bytes = calculate_stream_digests(stream)

    assert total_bytes == 0
    sha256 = next(d for d in digests if d.algorithm == DigestAlgorithm.SHA256)
    sha512 = next(d for d in digests if d.algorithm == DigestAlgorithm.SHA512)

    assert sha256.value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha512.value == (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    )


def test_nist_abc_string_hashes():
    # "abc" SHA-256 = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    stream = io.BytesIO(b"abc")
    digests, total_bytes = calculate_stream_digests(stream, chunk_size=1)

    assert total_bytes == 3
    sha256 = next(d for d in digests if d.algorithm == DigestAlgorithm.SHA256)
    assert sha256.value == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_streaming_multi_chunk_hashing():
    payload = b"A" * 100000  # 100 KB payload
    stream = io.BytesIO(payload)
    digests, total_bytes = calculate_stream_digests(stream, chunk_size=1024)

    assert total_bytes == 100000
    sha256 = next(d for d in digests if d.algorithm == DigestAlgorithm.SHA256)
    assert len(sha256.value) == 64
