# -*- coding: utf-8 -*-
"""
Created on Mon Dec 13 21:03:39 2021

@author: user
"""

from client_basics import *


P = curve.generator
n = curve.order
m = 28501
m_bytes = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')

def generate_keypair(P, n):
    Sa = random.randint(1, n-2)
    Qa = Sa * P
    return Sa, Qa

def generate_sign(P, n, Sa, m_bytes):
    k = Random.new().read(int(math.log(n,2)))
    k = int.from_bytes(k, byteorder='big')%n
    R = k*P
    r = (R.x) % n
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    temp = r_bytes + m_bytes
    hashVal = SHA3_256.new(temp)
    h = int.from_bytes(hashVal.digest(), 'big') % n
    s = (k - Sa * h) % n
    print("h= ", h)
    print("s= ",s)
    return h, s

def verify_sign(P, n, s, h, Qa, message):
    V = s*P + h*Qa
    v = (V.x) % n
    v_bytes = v.to_bytes((v.bit_length() + 7) // 8, byteorder='big')

    hashVal = SHA3_256.new(v_bytes + message)
    h_ver = int.from_bytes(hashVal.digest(), 'big') % n
    if h_ver == h:
        print("TRUE Verified!!!!!!!!!")   


Sa, Qa = generate_keypair(P, n)
print("Identitiy Key is created")
print("IKey is a long term key and shouldn't be changed and private part should be kept secret. But this is a sample run, so here is my private IKey: ",Sa)
print("\nMy ID number is: ",m)
print("Converted my ID to bytes in order to sign it: ",m_bytes)

print("\nSignature of my ID number is:")
h, s = generate_sign(P, n, Sa, m_bytes)
print("\nSending signature and my IKEY to server via IKRegReq() function in json format")
IKRegReq(h, s, Qa.x, Qa.y)


print("\nReceived the verification code through email")
code = input("Enter verification code which is sent to you: ")
print("Sending the verification code to server via IKRegVerify() function in json format")
IKRegVerify(int(code))


print("\nGenerating SPK...")
Sa2, SPKPUB = generate_keypair(P, n)
print("\nPrivate SPK: ", Sa2)
print("Public SPK.x:", SPKPUB.x)
print("Public SPK.y:", SPKPUB.y)

SPKPUB_x_bytes = SPKPUB.x.to_bytes((SPKPUB.x.bit_length() + 7) // 8, byteorder='big')
SPKPUB_y_bytes = SPKPUB.y.to_bytes((SPKPUB.y.bit_length() + 7) // 8, byteorder='big')
temp_message = SPKPUB_x_bytes + SPKPUB_y_bytes
print("\nConvert SPK.x and SPK.y to bytes in order to sign them then concatenate them result will be like: ", temp_message)

print("\nSignature of my SPK is:")
h2, s2 = generate_sign(P, n, Sa, temp_message)

print("\nSending SPK and the signatures to the server via SPKReg() function in json format...")
server_message = SPKReg(h2, s2, SPKPUB.x, SPKPUB.y)


print("\nServer's SPK Verification")
print("\nRecreating the message(SPK) signed by the server")

h3 = server_message[2]
s3 = server_message[3]
server_pubx = server_message[0]
server_puby = server_message[1]

server_pubx_bytes = server_pubx.to_bytes((server_pubx.bit_length() + 7) // 8, byteorder='big')
server_puby_bytes = server_puby.to_bytes((server_puby.bit_length() + 7) // 8, byteorder='big')
h3_bytes = h3.to_bytes((h3.bit_length() + 7) // 8, byteorder='big')
s3_bytes = s3.to_bytes((s3.bit_length() + 7) // 8, byteorder='big')
temp2 = server_pubx_bytes + server_puby_bytes
server_point = Point(server_pubx, server_puby, curve)

print("Verifying the server's SPK...\nIf server's SPK is verified we can move to the OTK generation step\nIs SPK verified?: ")
verify_sign(P,n,s3,h3,IKey_Ser,temp2)

print("\nCreating HMAC key (Diffie Hellman)")
T = Sa2 * server_point
Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
Ty_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
U = Tx_bytes + Ty_bytes + b'NoNeedToRideAndHide'
hashVal3 = SHA3_256.new(U)
k_HMAC = int.from_bytes(hashVal3.digest(), 'big') % n
k_HMAC_bytes = k_HMAC.to_bytes((k_HMAC.bit_length() + 7) // 8, byteorder='big')
print("\nT is ({} , {})".format(hex(T.x), hex(T.y)))
print("U is: ",U)
print("HMAC key is created ", k_HMAC_bytes)

print("\nCreating OTKs starting from index 0...")
for i in range(11):
    OTK0_private, OTK0 = generate_keypair(P, n)
    print("\n{}th key generated.".format(i))
    print("Private Part= ", OTK0_private)
    print("Public (x coordinate)=",OTK0.x)
    print("Public (y coordinate)=",OTK0.y)
    OTK0_x_bytes = OTK0.x.to_bytes((OTK0.x.bit_length() + 7) // 8, byteorder='big')
    OTK0_y_bytes = OTK0.y.to_bytes((OTK0.y.bit_length() + 7) // 8, byteorder='big')
    temp = OTK0_x_bytes + OTK0_y_bytes
    print("x and y coordinates of the OTK converted to bytes and concatanated")
    print("message: ", temp)
    hmac0 = HMAC.new(key=k_HMAC_bytes, msg=temp, digestmod=SHA256)
    print("\nhmac is calculated and converted with 'hexdigest()': ", hmac0.hexdigest())
    OTKReg(i, OTK0.x, OTK0.y, hmac0.hexdigest())


print("\nTrying to delete OTKs...")
h_del, s_del = generate_sign(P,n, Sa, m_bytes)
ResetOTK(h_del, s_del)

print("\nTrying to delete SPK...")
ResetOTK(h_del, s_del)


print("\nTrying to delete Identity Key...")
#ResetIK(440311)  #to delete Identity Key, update the reset code and uncomment it
