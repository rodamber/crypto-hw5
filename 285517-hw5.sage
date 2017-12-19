from base64 import b64encode, b64decode
import hashlib

sciper = '285517'
server = 'lasecpc28.epfl.ch'

# ------------------------------------------------------------------------------

#converting a raw ascii string to an integer and back
# compute the integer using the horner method
# ENDIAN CONVENTION:
# the character at address 0 is multiplied with 2^0
encf = lambda x,y: 2^8*x + y
def ascii2int(s):
	# the string has to be reverted so that s[0] gets multiplied by 2^(8*0)
	return reduce(encf, map(ord, s[::-1]) )

# convert back to ascii string. the parameter "width" says
# how many ascii characters do we want in output (so that we
# append sufficiently many zero characters)
def int2ascii(x,width):
	L=[]
	for i in xrange(width):
		# always take least significant 8 bits, convert to ASCII and then shift right
		L.append( chr(x%(2^8)) )
		x=x//(2^8)
	return "".join(L)

def divideBlocks(string, length): 
	return [string[0+i:length+i] for i in range(0, len(string), length)]

# ------------------------------------------------------------------------------

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
    msg = sciper + ' ' + b64encode(x) + '\n'
    return connect_server(server, port, msg)[:-2]


# ==========
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
    
    
