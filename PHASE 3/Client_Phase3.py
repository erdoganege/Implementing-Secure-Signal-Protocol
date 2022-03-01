# -*- coding: utf-8 -*-
"""
Created on Mon Dec 13 21:03:39 2021

@author: user
"""

from client_basics import *


P = curve.generator
n = curve.order
m = 25331
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

def create_KDF_chain(chain_no, KS_bytes):

    kenc_arr = []
    khmac_arr = []
    kdf_bytes = KS_bytes
    for i in range(chain_no):
        #print("GIRDIK")
        temp = kdf_bytes + b'LeaveMeAlone'
        hashVal = SHA3_256.new(temp)
        Kenc = int.from_bytes(hashVal.digest(), 'big') % n
        Kenc_bytes = Kenc.to_bytes((Kenc.bit_length() + 7) // 8, byteorder='big')   
        #print("Kenc{} is: {}".format(i+1, Kenc_bytes))

        temp =  Kenc_bytes + b'GlovesAndSteeringWheel'
        hashVal = SHA3_256.new(temp)
        Khmac = int.from_bytes(hashVal.digest(), 'big') % n
        Khmac_bytes = Khmac.to_bytes((Khmac.bit_length() + 7) // 8, byteorder='big')      
        #print("Khmac{} is: {}".format(i+1, Khmac_bytes))

        temp = Khmac_bytes + b'YouWillNotHaveTheDrink'
        hashVal = SHA3_256.new(temp)
        Knext = int.from_bytes(hashVal.digest(), 'big') % n
        Knext_bytes = Knext.to_bytes((Knext.bit_length() + 7) // 8, byteorder='big')  
        
        kdf_bytes = Knext_bytes
        kenc_arr.append(Kenc_bytes)
        khmac_arr.append(Khmac_bytes)

    return kenc_arr, khmac_arr

def Encryption(message, kenc, khmac):
    
    cipher = AES.new(kenc, AES.MODE_CTR)
    ciphertext = cipher.encrypt(message)
    hmac = HMAC.new(key=khmac, msg=ciphertext, digestmod=SHA256)
    hmac_ = hmac.digest()
    result = cipher.nonce + ciphertext + hmac_
    
    return int.from_bytes(result, byteorder="big")


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




print("\nTrying to delete OTKs... Because I forgot them")
h_del, s_del = generate_sign(P,n, Sa, m_bytes)
ResetOTK(h_del, s_del)

print("\nNew Feature: Checking the status of the inbox and keys! Just send your signature of ID number and your ID via Status method")
Status(m, h_del, s_del)


OTKs = {0: '', 1: '', 2: '', 3:'',4:'',5:'',6:'',7:'',8:'',9:''}
OTK_hmacs = {0: '', 1: '', 2: '', 3:'',4:'',5:'',6:'',7:'',8:'',9:''}
print("\nCreating OTKs starting from index 0...")
for i in range(11):
    OTK0_private, OTK0 = generate_keypair(P, n)
    if i < 10:
        OTKs[i] = [OTK0_private, OTK0.x, OTK0.y]
    OTK0_x_bytes = OTK0.x.to_bytes((OTK0.x.bit_length() + 7) // 8, byteorder='big')
    OTK0_y_bytes = OTK0.y.to_bytes((OTK0.y.bit_length() + 7) // 8, byteorder='big')
    temp = OTK0_x_bytes + OTK0_y_bytes
    hmac0 = HMAC.new(key=k_HMAC_bytes, msg=temp, digestmod=SHA256)
    OTK_hmacs[i] = hmac0.hexdigest()
    OTKReg(i, OTK0.x, OTK0.y, hmac0.hexdigest())
last_OTKID = 9
#print("\nOTKs are generated and registered. This is my full list of OTKs\n")
print(OTKs)

print("\nI'll request messages from the pseudo client. It will send me 5 messages. But this time no invalid hmac")
print("Signing my stuID with my private IK")
PseudoSendMsgPH3(h_del,s_del)

print("\nChecking the status of the inbox and keys...")
Status(m, h_del, s_del)

print("\nI'll get those messages one by one and decrypt them as I did in phase 2. I'll keep the decrypted messages to use later in grading part. ")
requests = []
for i in range(5):
    request_message = ReqMsg(h_del,s_del)
    requests.append(request_message)

KDFs = {0: [], 1: [], 2: [], 3:[], 4:[],5:[],6:[],7:[],8:[],9:[]}
plaintexts_pseudo_client = []

for i in range(len(requests)):
    client_ID = requests[i][0]
    OTKID = requests[i][1]
    msgID = requests[i][2]
    client_message = requests[i][3]
    EK_x = requests[i][4]
    EK_y = requests[i][5]
    #print("\nI got this from client {}: {}".format(client_ID, client_message))
    #print("Converting message to bytes to decrypt it...")
    client_message_bytes = client_message.to_bytes((client_message.bit_length() + 7) // 8, byteorder='big')
    #print("Converted message is: ", client_message_bytes)
    #print("\nSeperate nonce, ciphertext and hmac parts")
    nonce = client_message_bytes[:8]
    ciphertext = client_message_bytes[8:len(client_message_bytes)-32]
    hmac = client_message_bytes[len(client_message_bytes)-32:]

    #print("\nGenerating Session Key")
    otk_pri = OTKs[OTKID][0]
    EK = Point(EK_x, EK_y, curve)
    T = otk_pri * EK
    Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
    Ty_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
    U = Tx_bytes + Ty_bytes + b'MadMadWorld'    
    #print("U is: ", U)
    hashVal3 = SHA3_256.new(U)
    KS = int.from_bytes(hashVal3.digest(), 'big') % n
    KS_bytes = KS.to_bytes((KS.bit_length() + 7) // 8, byteorder='big')
    #print("Ks is:",KS_bytes)
    
    if msgID == 1:
        KDFs[OTKID].append(KS)

    for k in range(len(KDFs[OTKID])):
        kdf = KDFs[OTKID][k]
        kdf_bytes = kdf.to_bytes((kdf.bit_length() + 7) // 8, byteorder='big')

        temp = kdf_bytes + b'LeaveMeAlone'
        hashVal = SHA3_256.new(temp)
        Kenc = int.from_bytes(hashVal.digest(), 'big') % n
        Kenc_bytes = Kenc.to_bytes((Kenc.bit_length() + 7) // 8, byteorder='big')   
        #print("Kenc{} is: {}".format(k+1, Kenc_bytes))

        temp =  Kenc_bytes + b'GlovesAndSteeringWheel'
        hashVal = SHA3_256.new(temp)
        Khmac = int.from_bytes(hashVal.digest(), 'big') % n
        Khmac_bytes = Khmac.to_bytes((Khmac.bit_length() + 7) // 8, byteorder='big')      
       # print("Khmac{} is: {}".format(k+1, Khmac_bytes))

        temp = Khmac_bytes + b'YouWillNotHaveTheDrink'
        hashVal = SHA3_256.new(temp)
        Knext = int.from_bytes(hashVal.digest(), 'big') % n
        Knext_bytes = Knext.to_bytes((Knext.bit_length() + 7) // 8, byteorder='big')             
        #print("Kkdf{} is: {}".format(k+1, Knext_bytes))

    KDFs[OTKID].append(Knext)
    
    val = HMAC.new(Khmac_bytes, ciphertext, digestmod=SHA256)
    calculated_hmac = val.digest()
    #print("\nCalculated hmac: ", calculated_hmac)
    if calculated_hmac == hmac:
        #print("Hmac verified")
        cipher = AES.new(Kenc_bytes, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        print("\nCreate an AES object with Kenc then decrypt the ciphertext:\nPlaintext is:",plaintext.decode('utf-8'))
        plaintexts_pseudo_client.append(plaintext.decode('utf-8'))

print("Saving the collected plaintext somewhere")
for i in plaintexts_pseudo_client:
    print(i)

friend_id = 18007
friend_id_bytes = friend_id.to_bytes((friend_id.bit_length() + 7) // 8, byteorder='big')
print("Now I want to send messages to my friend. Her id is 18007. Yes she is also imaginary")
print("Signing The stuIDB of party B with my private IK")
h_friend, s_friend = generate_sign(P,n, Sa, friend_id_bytes)

friend_return = reqOTKB(m, friend_id, h_friend, s_friend)
print("The other party's OTK public key is acquired from the server ...")
friend_OTKID = friend_return[0]
friend_OTK_x = friend_return[1]
friend_OTK_y = friend_return[2]



print("\nGenerating Ephemeral key")
pri_EK = random.randint(1, n-2)
my_EK = pri_EK * P
sending_message = "Hello darkness my old friend"
#print("This is my message:", sending_message)
sending_message = b"Hello darkness my old friend"

friend_OTK_pub = Point(friend_OTK_x,friend_OTK_y, curve)

T = friend_OTK_pub * pri_EK
Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
Ty_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
U = Tx_bytes + Ty_bytes + b'MadMadWorld'    

hashVal3 = SHA3_256.new(U)
KS = int.from_bytes(hashVal3.digest(), 'big') % n
KS_bytes = KS.to_bytes((KS.bit_length() + 7) // 8, byteorder='big')


print("\nGenerating session key using my EK and my friends Public OTK/ Phase 3...")
kenc_arr, khmac_arr = create_KDF_chain(5, KS_bytes)

print("Sending the message to the server, so it would deliver it to my friend whenever she is active ...")
print("U is:", U)
print("Ks is:",KS_bytes)
for i in range(len(kenc_arr)):
    sending_message = bytes(plaintexts_pseudo_client[i], 'utf-8')
    my_message = Encryption(sending_message, kenc_arr[i], khmac_arr[i])
    print("Kenc{} is: {}".format(i+1, kenc_arr[i]))
    print("Khmac{} is: {}".format(i+1, khmac_arr[i]))
    SendMsg(m, friend_id, friend_OTKID, i+1, my_message, my_EK.x, my_EK.y)


print("\nChecking the status of the inbox and keys...")
abc = Status(m, h_del, s_del)
if abc[1] != 10:
    for i in range(10-abc[1]):
        OTK0_private, OTK0 = generate_keypair(P, n)
        OTKs[last_OTKID+1] = [OTK0_private, OTK0.x, OTK0.y]
        OTK0_x_bytes = OTK0.x.to_bytes((OTK0.x.bit_length() + 7) // 8, byteorder='big')
        OTK0_y_bytes = OTK0.y.to_bytes((OTK0.y.bit_length() + 7) // 8, byteorder='big')
        temp = OTK0_x_bytes + OTK0_y_bytes
        hmac0 = HMAC.new(key=k_HMAC_bytes, msg=temp, digestmod=SHA256)
        OTKReg(last_OTKID+1, OTK0.x, OTK0.y, hmac0.hexdigest())
        last_OTKID += 1

#print(OTKs)
Status(m, h_del, s_del)
'''
print("\nEncrypting the message with Kenc1 and created a mac value with Khmac1. Then created msg in this format: nonce+cipher+hmac. Converted to int to be able to send it")
my_message = Encryption(sending_message, kenc_arr[0], khmac_arr[0])
print("Sending the message to the server, so it would deliver it to my friend whenever she is active ...")
SendMsg(m, friend_id, friend_OTKID, 1, my_message, my_EK.x, my_EK.y)



sending_message = "I've come to talk with you again"
print("I'll send one more message in the same block:", sending_message)
sending_message = b"I've come to talk with you again"
kenc_arr, khmac_arr = create_KDF_chain(2, KS_bytes)
for i in range(1, len(kenc_arr)):
    print("Kenc{} is: {}".format(i+1, kenc_arr[i]))
    print("Khmac{} is: {}".format(i+1, khmac_arr[i]))
my_message = Encryption(sending_message, kenc_arr[1], khmac_arr[1])
print("Sending the message to the server, so it would deliver it to pseudo-client/user whenever it is active ...")
SendMsg(m, friend_id, friend_OTKID, 2, my_message, my_EK.x, my_EK.y)
'''











##My verification
'''
client_message_bytes = my_message.to_bytes((my_message.bit_length() + 7) // 8, byteorder='big')
nonce = client_message_bytes[:8]
ciphertext = client_message_bytes[8:len(client_message_bytes)-32]
cipher = AES.new(kenc_arr[0], AES.MODE_CTR, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)
print("\nCreate an AES object with Kenc then decrypt the ciphertext:\nPlaintext is:",plaintext.decode('utf-8'))
'''