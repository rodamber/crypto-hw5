load('285517/285517-parameters.sage')
load('tutorial_5.sage')

from base64 import b64encode, b64decode

import hashlib


sciper = str(Sciper)
server = 'lasecpc28.epfl.ch'

# ==============================================================================
# Exercise 1

port1 = 5555

def query1(x):
    msg = sciper + ' ' + b64encode(x) + '\n'
    return connect_server(server, port1, msg)[:-2]

def pad(m):
    hash = hashlib.sha256(m).digest()

    lhs = '0' * (2**17 - len(m) * 8 - 12)
    rhs = ''.join(map(lambda x: '{:b}'.format(ord(x)) , hash))[:12]

    return ''.join(map(lambda x: chr(int(x, 2)), divideBlocks(lhs + rhs, 8)))



def solve1(M1):
    m = M1 + chr(0)

    while m + pad(m) != M1 + pad(M1):
          m += chr(0)

    return query1(m)


# ==============================================================================
# Exercise 2

def solve2(p, q, g, M1, r1, c1, M2):
    Zp = Integers(p)
    Zq = Integers(q)

    g  = Zp(g)
    r1 = Zq(r1)

    x1 = ascii2int(M1)
    G1 = g ** x1
    a1 = hashlib.sha256(int2binascii(G1.lift(), 2**7)).digest()

    x2 = ascii2int(M2)
    G2 = g ** x2
    a2 = hashlib.sha256(int2binascii(G2.lift(), 2**7)).digest()

    Q2 = r1 * (x1 * binascii2int(a1)) / (x2 * binascii2int(a2))
    assert Q2 * (x2 * binascii2int(a2)) == r1 * (x1 * binascii2int(a1))

    return Q2


# ==============================================================================
# Exercise 3

def solve3(p, q, g, y, m, n, M1, M2, r1, s1, r2, s2):
    Zp = Integers(p)
    Zq = Integers(q)

    H1 = ascii2int(hashlib.sha256(M1).digest())
    H2 = ascii2int(hashlib.sha256(M2).digest())

    A = matrix(Zq, [[s2 * m, -r2],  [s1, -r1]])
    B = vector(Zq, [H2 - s2 * n, H1])

    k1, x = A.solve_right(B)

    assert Zq(Zp(g) ** k1) == r1, '\n{}\n{}'.format(Zq(Zp(g) ** k1), r1)
    assert (Zp(g) ** x) == y,  '\n{}\n{}'.format((Zp(g) ** x), y)

    return x


# ==============================================================================
# Exercise 4

port4 = 6666
username = sciper[:6]
ci = connection_interface(server, port4)

def init():
    ci.connect()
    ci.send('0 {}\n'.format(username))

    m, b, session = ci.recv().split()
    return b64decode(m), b, session

def send(response, session):
    ci.send('1 {} {} {}\n'.format(username, response, session))

def recv():
    x = ci.recv().split()

    if len(x) == 1:
        if x[0] == '2':
            return 0
        elif x[0] == '3':
            return 1
        else:
            raise ValueError('x[0] = {}'.format(x[0]))
    else:
        if len(x) != 2:
           raise ValueError('len(x) = {}'.format(len(x)))

        b, session = x
        return b, session

def secret(w):
    padding = '0' * (16 - len(w))
    return aes_encrypt(w + padding, 0)

def res(a, i, ch):
    if ch == '0':
        return a[2 * i + 1]
    else:
        return a[2 * i]

def interact(a, b, c, session):
    for i in range(64):
        assert(b == a[2 * i + c[i]])
        send(res(a, i, b), session)

        x = recv()
        if x in (0, 1) :
            if x == 0:
                print('Failure.')
            else:
                print('Success.')
            return x

        b, session = x

def ascii2bin(x):
    return ''.join(map(lambda y: '{0:08b}'.format(ord(y)), x))

def solve4():
    with open('passwords.txt', 'r') as f:
         for i, line in enumerate(f):
             print i
             passwd = line[:-1]

             m, b, session = init()

             # FIXME: We're treating 'a' as if it was a binary string, but it is
             # an ascii string!
             a = xor(passwd, m)
             c = hashlib.sha1(username + m).digest()[:8]

             if interact(a, b, c, session) == 1:
                 return passwd

# We know $c$, so we know every $k$, i.e., for every $i$ we know the index in $a$
# of the bit $ch_i$.

# When the server proposes a challenge $ch_i = a_{2i + c_i}$, we make a guess.
# Let's say our guess is one.

# If we got it right, then $a_{2i + 1 - c_i} = 1$.
# If we got it wrong, then $a_{2i + 1 - c_i} = 0$.

# I.e., $a_{2i + 1 - c_i} = 1_{guess is right}$, where $1$ is the indicator
# function.

# With this, we have both $a_k = ch_i$ and $a_{2i + 1 - c_i}$ (which is the other
# one of the two).

# After this, we just have to xor the two bits we got with the corresponding bits
# in $m$, to get two bits of the shares secret $s$.

# After we have $s$ we just have to search for a key $w$ (a password) in passwords.txt
# such that when we decrypt $0$ with $w$ we get $s$ as result.

# Note that after each time you fail you need to restart the protocol and use the
# partial info you have about $s$ in order to get to the later challenges.


# Algorithm:
#   i <- 0
#   s <- '0' * 128

#   while i < 64 do
#     c <- trunc_64(sha1(username||m))


# ==============================================================================
# Exercise 5

def solve5():
    pass