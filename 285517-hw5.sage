from base64 import b64encode, b64decode
from Crypto.Util import strxor
from Crypto.Cipher import AES

import hashlib
import sys
import socket


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

def xor(a,b):
    return strxor.strxor(a,b)

def aes_encrypt(message, key):
    obj = AES.new(key, AES.MODE_ECB,'')
    return obj.encrypt(message)

def aes_decrypt(message, key):
    obj = AES.new(key, AES.MODE_ECB,'')
    return obj.decrypt(message)

# You can interactively communicate with a server by using this class
# You can use this class as follows,
# my_connection = connection_interface(server_to_connect, port_to_connect)
# my_connection.connect()
# my_connection.send("blablabla\n")
# res = my_connection.recv()
# my_connection.disconnect()
class connection_interface:
  def __init__(self, server_name, port):
    self.target = (server_name, int(port))
    self.connected = False

  def connect(self):
    if not self.connected:
      self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.s.connect(self.target)
      self.connected = True

  def disconnect(self):
    if self.connected:
      self.s.close()
      self.connected = False

  # Sends a message to the server
  # The message must be finished with '\n'
  def send(self, msg):
    if self.connected:
      self.s.send(msg)
    else:
      raise Exception("You are not connected")

  # we use '\n' as terminator of a message
  def recv(self):
    if self.connected:
      try:
        buf = self.s.recv(1024)
        while buf[-1] != '\n':
          buf += self.s.recv(1024)

        return buf
      except IndexError:
        self.connected = False
        raise Exception("You are disconnected")
    else:
      raise Exception("You are not connected")

  def reconnect(self):
    self.disconnect()
    self.connect()


# ==============================================================================
# Helpers

sciper = '285517'
server = 'lasecpc28.epfl.ch'

def query(x, port):
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


# ==============================================================================
# Exercise 4

ex4_port = 6666
username = sciper[:6]
ci = connection_interface(server, ex4_port)

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
        assert(b == c[i])
        send(res(a, i, b), session)

        x = recv()
        if x in (0, 1) :
            if x == 0:
                print('Failure.')
            else:
                print('Success.')
            return x

        b, session = x

def solve4():
    with open('passwords.txt', 'r') as f:
         for i, line in enumerate(f):
             print i
             passwd = line[:-1]

             m, b, session = init()

             a = xor(passwd, m)
             c = hashlib.sha1(username + m).digest()[:8]

             if interact(a, b, c, session) == 1:
                 return passwd


# ==============================================================================
# Exercise 5

def solve5():
    pass