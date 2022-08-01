# GF(2^128)
# p = x^128+x^7+x^2+x+1
# p = 340282366920938463463374607431768211591

# Returns the degree of the polynomial
def deg(a):
    return len(bin(a)[2:]) - 1


# Multiplicative over GF(2^k)
def gf_mul(a, b, m):
    # Peasant multiplication from wikipedia
    p = 0
    while a > 0:
        if a & 1:
            p = p ^ b

        a = a >> 1
        b = b << 1

        # Modulus the polynomial m
        if deg(b) == deg(m):
            b = b ^ m
    return p
