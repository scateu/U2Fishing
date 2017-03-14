import binascii, ecdsa

# From Serial Output:
#87a51f87278d0c52f84ec247ba9aaee824d6bca95eda24703652053ca1d06847ea8b37e208b210caaa1020e9f9e1e1b47ff4bbf6c4718ab09cb2c0c
#U2F_CONFIG_LOAD_ATTEST_KEY
#761d25a9cc2f23c8c9266a5a201abce184caf09c241586c36364c87227ea71a88b37e208

att = binascii.unhexlify("a51f87278d0c52f84ec247ba9aaee824d6bca95eda24703652053ca1d06847ea8b37e208b210caaa1020e9f9e1e1b47ff4bbf6c4718ab09cb2c0c"[:32*2]) # the heading '87' is opcode of 'U2F_CONFIG_LOAD_ATTEST_KEY'
print att

attestkey = ecdsa.SigningKey.from_pem(open("key.pem").read())  #  prime256v1 ECC private key in PEM format
print attestkey.to_string() # a format without curve type or public key, only private key included. 
#print attestkey.to_pem()
#print attestkey.to_der()

## OUTPUT | xxd
#
#0000: a51f 8727 8d0c 52f8 4ec2 47ba 9aae e824  ...'..R.N.G....$
#0010: d6bc a95e da24 7036 5205 3ca1 d068 47ea  ...^.$p6R.<..hG.


# To Examine `key.pem`
#
#$ openssl ec -in key.pem -text -noout 
#Private-Key: (256 bit)
#priv:
#    00:a5:1f:87:27:8d:0c:52:f8:4e:c2:47:ba:9a:ae:
#    e8:24:d6:bc:a9:5e:da:24:70:36:52:05:3c:a1:d0:
#    68:47:ea
#pub: 
#    04:fb:80:20:f6:00:52:16:d1:11:ef:cb:2c:66:38:
#    52:29:06:6a:40:4b:f7:39:e1:d4:9c:9e:48:0d:fe:
#    8b:f8:6f:f9:81:56:c5:11:07:28:c4:a8:ff:10:1b:
#    bf:51:2e:cd:a9:61:49:df:8a:64:4a:08:d1:97:99:
#    6c:e3:90:66:b7
#ASN1 OID: prime256v1
#NIST CURVE: P-256
