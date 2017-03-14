import time, os, sys, array, binascii, signal, random, hashlib

def get_write_mask(key):
    m = hashlib.new('sha256')
    m.update(key + '\x15\x02\x01\x00\xee\x01\x23' + ('\x00'*57))
    h1 = m.hexdigest()
    m = hashlib.new('sha256')
    m.update(binascii.unhexlify(h1))
    h2 = m.hexdigest()

    return h1 + h2[:8]

#wkey = [random.randint(0,255)&0xff for x in range(0,32)]
#rkey = [random.randint(0,255)&0xff for x in range(0,32)]

# From Serial Port output:
# master key: 6b58151a51298547011e6076606f0d49a55d3e6298bcfec0a26d8bbc544d328c

wkey = binascii.unhexlify("6b58151a51298547011e6076606f0d49a55d3e6298bcfec0a26d8bbc544d328c")
print get_write_mask(wkey)

# Output: 761d25a9cc2f23c8c9266a5a201abce184caf09c241586c36364c87227ea71a88b37e208

# Just as the sequence from cert.c:

#code uint8_t WMASK[] = "\x76\x1d\x25\xa9\xcc\x2f\x23\xc8\xc9\x26\x6a\x5a\x20\x1a\xbc\xe1\x84\xca\xf0\x9c"
#"\x24\x15\x86\xc3\x63\x64\xc8\x72\x27\xea\x71\xa8\x8b\x37\xe2\x08";
#code uint8_t RMASK[] = "\x1a\x1a\x81\x7b\xa8\x0a\x9b\x8f\x23\x08\xbd\xcb\x6c\x1c\xb6\x99\x47\x4a\xe9\xbb"
#"\x2c\x67\xbd\x58\x82\x66\xdd\x94\x6b\x66\x06\xd8\xd5\x51\x6c\xc9";
