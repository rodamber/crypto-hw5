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

    g = Zp(g)
    r1 = Zq(g)

    x1 = ascii2int(M1)
    G1 = g ** x1
    a1 = hashlib.sha256(int2binascii(G1.lift(), 10)).digest()
    h1 = g ** binascii2int(a1)

    assert c1 == G1 * h1 ** r1, 'c1 == ' + str(c1) + '\nG1 * h1**r1 == ' + str(G1 * h1**r1)

