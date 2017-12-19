#####
#################### Exercises 2,3, 4 and 5 ##########
#####    



##################################################
# Encoding/representations of binary values
##################################################
# In this homework, we need to manipulate binary 
# in various representations (sometimes raw ascii
# sometimes as integers etc.) 
# Here we give you methods of conversion between
# these representations. 
#
# WARNING: we give you more methods than you 
#			  need for the homework! You just need 
#			  to pick whatever is useful for you.
##################################################


#Convert a string written in hexadecimal into its numerical value
a = int("0b",16) #int("0x0b",16) would work as well
print "a =",a

#Convert a string written in binary into its numerical value
b = int("1011001",2) 
print "b =",b

#Convert an integer back into a hexadecimal string
#The 02 indicates the desired size of the string (for printing leading zeros)
#The integer a should be 0 <= a <= 255. This can be of course changed to anything
# e.g. s = "{:064X}".format(a)
#
# IF a IS A MODULAR INTEGER, DON'T FORGET TO LIFT!!!
#
s = "{:02X}".format(a)
print "a in hexa =",s

#Convert an integer back into a binary string
#The 08 indicates the desired size of the string (for printing leading zeros)
#The integer a should be 0 <= a <= 255
s = '{0:08b}'.format(b)
print "a in binary =",s

c1 = int("11",16)
c2 = int("12",16)
print "c1 =", "{:02X}".format(c1)
print "c2 =", "{:02X}".format(c2)
c3 = int("11001100", 2)
c4 = int("10100110", 2)
print "c3 =", '{0:08b}'.format(c3)
print "c4 =", '{0:08b}'.format(c4)
b1 = int("0", 2)
b2 = int("1", 2)
print "b1 =", '{0:b}'.format(b1)
print "b2 =", '{0:b}'.format(b2)


# Converting raw ascii strings (binary strings with groups of 8 bits packed into characters)
# to hexadecimal and back
import binascii
c3 = "abcdefghijklmnop"
# Encode ascii as hex string
c3_hex = binascii.b2a_hex(c3) # or c3_hex = c3.encode("hex")
print c3_hex
# Decode from hex string to string
c3 = binascii.a2b_hex(c3_hex) # or  c3 = c3_hex.decode("hex")
print c3


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


print '----------------------------------------'


##################################################
# Bit operations in SAGE and AES
##################################################
# In this HW, you need to do some AES encryptions
# and XORs of binary strings.
# If the binary strings are represented as 
# vectors over Z_2, then xor is simply done 
# by addition.
# If the strings are represented as raw ascii
# you can use the code we give to you here.
##################################################


#XOR of strings, AES

from Crypto.Util import strxor
from Crypto.Cipher import AES

"""
performs the xor of string a and b (every character is treated as an 8-bit value)
"""
def xor(a,b):
    return strxor.strxor(a,b)

    
#AES encryption of message <m> with ECB mode under key <key>
def aes_encrypt(message, key):
    obj = AES.new(key, AES.MODE_ECB,'')
    return obj.encrypt(message)
    
#AES decryption of message <m> with ECB mode under key <key>
def aes_decrypt(message, key):
    obj = AES.new(key, AES.MODE_ECB,'')
    return obj.decrypt(message)

message = "abcdefghijklmnop"
key = "aabbaabbaabbaabb"
ciphertext = aes_encrypt(message, key)

hex_ciphertext = ciphertext.encode("hex")

print "If we try to print the ciphertext there are many unprintable characters:", ciphertext

print "So we print it in hexadecimal:", hex_ciphertext

#We get back the ciphertext 
ciphertext = hex_ciphertext.decode("hex")

plaintext = aes_decrypt(ciphertext, key)
print "the plaintext is:", plaintext

print '----------------------------------------'

#################################################
# base 64
##################################################
# we provide some parameters encoded in base64.
# Although we describe the encoding using binary
# strings in the HW document, it is more 
# practical to encode from/decode to (raw) ASCII
# as given in this example.
##################################################

import base64

# To encode the string 'Red Fox!' we call:
encoded_b64 = base64.b64encode("Red Fox!")
print encoded_b64

# to decode we call
print base64.b64decode(encoded_b64)

print '----------------------------------------'
