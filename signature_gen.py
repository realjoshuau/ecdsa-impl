# ecdsa signature and breaking implementation
# based off of "https://www.youtube.com/watch?v=-UcCMjQab4w"

import hashlib
from ecdsa import NIST192p, SigningKey, VerifyingKey
from ecdsa.ellipticcurve import Point
from ecdsa.numbertheory import inverse_mod
from ecdsa.util import sigencode_der

# using 192p curve

def generate_signature(message: str, private_key: str) -> str:
    # https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    e = int(hashlib.sha256(message.encode("utf-8")).hexdigest(), 16) 
    n = NIST192p.order
    k = int(4) 
    # Calculate the point (x1, y1) = k * G
    G = NIST192p.generator
    point = G * k
    x1 = point.x()
    r = x1 % n     # Calculate r = x1 mod n
    if r == 0:
        raise ValueError("r cannot be zero, choose a different k")
    # Calculate s = k^(-1) * (E + d * r) mod n, where d is the private key
    s = pow(k, n - 2, n) * (e + int(private_key, 16) * r) % n
    if s == 0:
        raise ValueError("s cannot be zero, choose a different k")
    signature = (r, s)
    signature_hex = f"{signature[0]:x}{signature[1]:x}" # :x converts to hex
    return signature_hex

def verify_signature(message: str, signature: str, public_key: tuple) -> bool:
    # Split the signature into r and s
    r = int(signature[:len(signature)//2], 16)
    s = int(signature[len(signature)//2:], 16)
    n = NIST192p.order
    if not (1 <= r < n and 1 <= s < n):
        return False
    # Calculate E = HASH(M)
    e = int(hashlib.sha256(message.encode("utf-8")).hexdigest(), 16)
    w = pow(s, n - 2, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    # Calculate the point (x1, y1) = u1 * G + u2 * Q, where Q is the public key point
    G = NIST192p.generator
    Qx = int(public_key[0], 16) # since public key is a Point
    Qy = int(public_key[1], 16)
    Q = Point(NIST192p.curve, Qx, Qy)
    R = G * u1 + Q * u2
    x1 = R.x()
    # Calculate v = x1 mod n
    v = x1 % n
    # The signature is valid if v == r
    return v == r



def break_signature(text1: str, text2: str, signature1: str, signature2: str) -> str:
    # Since K is "fixed" in this implementation, we can break the signature by finding the private key
    r1 = int(signature1[:len(signature1)//2], 16)
    s1 = int(signature1[len(signature1)//2:], 16)
    r2 = int(signature2[:len(signature2)//2], 16)
    s2 = int(signature2[len(signature2)//2:], 16)
    # r1 and r2 should be equal since k is fixed
    print("r1: ", r1)
    print("s1: ", s1)
    print("r2: ", r2)
    print("s2: ", s2)
    assert r1 == r2, "r values must be equal for the same k"
    print("r values are equal, can calculate private key")
    n = NIST192p.order
    e1 = int(hashlib.sha256(text1.encode("utf-8")).hexdigest(), 16)
    e2 = int(hashlib.sha256(text2.encode("utf-8")).hexdigest(), 16)
    # Calculate k using the two signatures
    k = (((e1 - e2) % n * inverse_mod(s1 - s2, n)) % n) # timestamp - 7:28
    print("Found k value: ", k)
    assert k == 4, "k value not 4 as expected (check inputs?)"
    # Calculate the private key using the formula: d = (s1 * k - e1) / r1 mod n
    d = (s1 * k - e1) * inverse_mod(r1, n) % n 
    return hex(d)

def to_der(r, s):
    return sigencode_der(r, s, NIST192p.order)

def parse_signature(signature_hex):
    half = len(signature_hex) // 2
    r = int(signature_hex[:half], 16)
    s = int(signature_hex[half:], 16)
    return to_der(r, s)

if __name__ == "__main__":
    # Example usage
    private_key, public_key = ('0x19c80a2989469305a931a4b01c80787be2d584effa51d9c6', ('0xb97b16f8bd741ff22c531b518184d73c94b797c027e63b3c', '0xac809edb6b100f3c479fefc7e2ff4da3c83273dae25a0c7d'))
    print(f"Private Key: {private_key}")
    print(f"Public Key: {public_key[0]}, {public_key[1]}")
    print("--------- Message 1")
    message = "Hello world."
    signature = generate_signature(message, private_key)
    print(f"Message: {message}, Signature: {signature}, SignatureR: {signature[:len(signature)//2]}, SignatureS: {signature[len(signature)//2:]}")
    is_valid = verify_signature(message, signature, public_key)
    print(f"Is the signature valid? {is_valid}")
    print("--------- Message 2")
    message2 = "A second message."
    signature2 = generate_signature(message2, private_key)
    print(f"Message: {message2}, Signature: {signature2}, SignatureR: {signature2[:len(signature2)//2]}, SignatureS: {signature2[len(signature2)//2:]}")
    is_valid2 = verify_signature(message2, signature2, public_key)
    print(f"Is the signature valid? {is_valid2}")
    print("--------- Message 3")
    message3 = "A third message."
    signature3 = generate_signature(message3, private_key)
    print(f"Message: {message3}, Signature: {signature3}, SignatureR: {signature3[:len(signature3)//2]}, SignatureS: {signature3[len(signature3)//2:]}")
    is_valid3 = verify_signature(message3, signature3, public_key)

    print("--------- Breaking the signature")
    calc_priv_key = break_signature(message, message2, signature, signature2)
    assert private_key == calc_priv_key, "Private key should have been recovered successfully"
    print(f"Private key successfully recovered: {calc_priv_key}")
    fake_sign_1 = generate_signature("Hacked message.", calc_priv_key)
    print(f"Fake signature for 'Hacked message.': {fake_sign_1}")
    is_fake_valid = verify_signature("Hacked message.", fake_sign_1, public_key)
    print(f"Is the fake signature valid? {is_fake_valid}")
    
    print("--------- Breaking the signature with a different message")
    calc_priv_key2 = break_signature(message, message3, signature, signature3)
    assert private_key == calc_priv_key2, "Private key should have been recovered successfully with a different message"
    print(f"Private key successfully recovered: {calc_priv_key2}")
    fake_sign_2 = generate_signature("Another hacked message.", calc_priv_key2)
    print(f"Fake signature for 'Another hacked message.': {fake_sign_2}")
    is_fake_valid2 = verify_signature("Another hacked message.", fake_sign_2, public_key)
    print(f"Is the fake signature valid? {is_fake_valid2}")

    # Attempt to verify & break the signature using the ECDSA library
    sk = SigningKey.from_string(bytes.fromhex(private_key[2:]), curve=NIST192p)
    vk: VerifyingKey = sk.get_verifying_key()
    print("--------- ECDSA Library Verification")
    print("Private Key: ", sk.to_string().hex())
    print("Public Key: ", vk.to_string().hex())
    assert sk.to_string().hex() == private_key[2:], "Private key from ECDSA library should match"
    assert vk.to_string().hex() == public_key[0][2:] + public_key[1][2:], "Public key from ECDSA library should match"

    print("Verifying signature with ECDSA library...")
    assert vk.verify(parse_signature(signature), message.encode("utf-8")), "Signature verification with ECDSA library failed"