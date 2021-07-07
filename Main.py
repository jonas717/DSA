import DSA
import hashlib

str = "Hello my name is Jonas."

hash = int(hashlib.sha256(str.encode()).hexdigest(), 16)

# find prime pair in given range
p,q = DSA.find_prime_pair(10000, 100000)

print(f"Prime p is {p} and prime q is {q}.")

# find element g

g = DSA.find_element_g(p, q)

print(f"Element g is {g}")

# get key pair
sk, pk = DSA.generate_key_pair(p, q, g)

print(f"Secret key is {sk} and the public key is {pk}")

print(hash)

# signature
k = 0
r = 0
s = 0

iterations = 0
iterations_outside = 0

while s == 0:
    while r == 0:
        if iterations > 20:
            break
        k = DSA.pick_k(q)
        r = DSA.calculate_r(g, k, p, q)
        iterations += 1

    if iterations_outside > 20:
            break
    s = DSA.calculate_s(k, r, sk, hash, q)
    iterations_outside += 1


signature = (k, r, s)

if signature[0] == 0 or signature[1] == 0:
    print(f"Could not be signed. Repeat the algorithm.")
else:
    print(f"The signature is {signature}.")
# validation
    w = DSA.calculate_w(s, q)
    u = DSA.calculate_u(w, hash, q)
    v = DSA.calculate_v(w, r, q)
    z = DSA.calculate_z(g, u, pk, v, p, q)
    
    print(f"z is {z}")

    if z == signature[1]:
        print(f"Signature is verified with r = {signature[1]} and z = {z}.")
    else: 
        print(f"Signature is not valid with r = {signature[1]} and z = {z}.")

