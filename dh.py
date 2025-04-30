PRIME = 19  # p
BASE = 2    # g

def mod_pow(base, exponent, modulus):
    
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

# call this when you want to send your result key(generated)
def generate_public_key(private_key):  
    return mod_pow(BASE, private_key, PRIME)

# After receiving the peer result, call this to calculate the shared key.
def calculate_shared_key(peer_public_key, private_key): 
    return mod_pow(peer_public_key, private_key, PRIME)
