from base64 import b64encode, b64decode
import hashlib


# ==============================================================================
# Tutorial code

def divideBlocks(string, length): 
	return [string[0+i:length+i] for i in range(0, len(string), length)]

def binascii2int(s):
    return reduce(lambda x,y: (x<<8) + ord(y), s, 0 )

def int2binascii(x,width):
    L=[]
    for i in xrange(width):
        # always take least significant 8 bits, convert to ASCII and then shift right
        L.append( chr(x & 0xff) )
        x=x>>8
    #revert to have correct endian
    return "".join(L[::-1])

def ascii2int(s):
    # the string has to be reverted so that s[0] gets multiplied by 2^(8*0)
    return reduce(lambda x,y: (x<<8) + ord(y), s[::-1], 0 )

def int2ascii(x):
    L=[]
    while(x>0):
        # always take least significant 8 bits, convert to ASCII and then shift right
        L.append( chr(x & 0xff) )
        x=x>>8
    return "".join(L)

def connect_server(server_name, port, message):
    import sys
    import socket

    server = (server_name, int(port))
    sock   = socket.create_connection(server)

    sock.send(message)
    response=''

    while True:
        data = sock.recv(9000)

        if not data:
            break

        response += data

    sock.close()
    return response

def query(x, port):
    sciper = '285517'
    server = 'lasecpc28.epfl.ch'

    msg = sciper + ' ' + b64encode(x) + '\n'
    return connect_server(server, port, msg)[:-2]


# ==============================================================================
# Exercise 1

ex1_port = 5555

def pad(m):
    hash = hashlib.sha256(m).digest()

    lhs = '0' * (2**17 - len(m) * 8 - 12)
    rhs = ''.join(map(lambda x: '{:b}'.format(ord(x)) , hash))[:12]

    return ''.join(map(lambda x: chr(int(x, 2)), divideBlocks(lhs + rhs, 8)))

    

def solve1(M1):
    m = M1 + chr(0)

    while m + pad(m) != M1 + pad(M1):
          m += chr(0)

    return query(m, ex1_port)
    
    
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

solve3(p3, q3, g3, y3, m3, n3, M31, M32, r31, s31, r32, s32)