import socket
import struct
import sys
import getpass
import threading
import time

class msg_preauth:
    #Def from net/message.h:99
    #Message consists of 1 byte message type, 3 is
    #MSGTYPE_PREAUTHENTICATE
    #2 byte message length
    #4 byte Planeshift Net ID,
    #according to net/messages.h:48 it is 0x00B9
    msgtype = 3
    msgdef = "<BHI"
    msglen = 4
    msgpayload = ()

    def append(self, content):
        self.msgpayload = (self.msgtype, self.msglen, content)

class msg_preautapprove:
    msgtype = 4
    msgdef = "<BHI"
    msglen = 4
    msgpayload = ()

    def append(self, content):
        self.msgpayload = (self.msgtype, self.msglen, content)
    
class msg_auth:
    msgtype = 2
    splitmsgdef = (
        "I",
        "c",
        "c",
        "c",
        "c",
        "c",
        "c",
        "H",
        "H",
        "c",
        "c")
    msgdef = "<BH"
    msglen = 8
    msgheaderlen = 3
    msgpayload = (msgtype, msglen)
    curappendpos = 0

    def append(self, content):
        msgpayload[curappendpos] = content
        
        adddef = splitmsgdef[curappendpos]

        #We need to figure out how long the text is
        isdynstring = adddef == "c"
        
        if(isdynstring):
            adddef = len(content) + adddef
            #Strings are null terminated (same as adding one empty byte after each string?)
            msgpayload[curappendpos] += "\0"
            
        msgdef += adddef
        
        if(isdynstring):
            msglen = struct.calcsize(msgdef) - msgheaderlen
        
        curappendpos += 1

def makepacket(msg):
    message = struct.pack(msg.msgdef, *msg.msgpayload)

    pktdef = "<IIIHB"
    pktlen = struct.calcsize(msg.msgdef) #It is only the message
    #Def from net/netpacket.h:51
    #4 byte message id, unique for every message?
    #4 byte offset
    #4 byte message length
    #2 byte length for whole package
    #1 byte flags
    #And then append message
    packet = struct.pack(pktdef, 1, 0, pktlen, pktlen, 0x01)
    packet += message;
    reallen = struct.calcsize(pktdef) + pktlen

    return (packet, reallen)

class mysocket:
    def __init__(self, sock=None):
        if sock is None:
            self.sock = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setblocking(0)
        else:
            self.sock = sock

    def connect(self, host, port):
        self.sock.connect((host, port))

    def mysend(self, msg, msglen):
        totalsent = 0
        while totalsent < msglen:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent

    def myreceive(self):
        chunks = []
        bytes_recd = 0
        msglen = 1400
        #while bytes_recd < msglen:
        chunk = self.sock.recv(min(msglen - bytes_recd, 2048))
        if chunk == '':
            raise RuntimeError("socket connection broken2")
            
        #chunks.append(chunk)
        #bytes_recd = bytes_recd + len(chunk)
        return chunk

sendlist = []

def network_loop():
    s = mysocket()
    s.connect("planeshift.teamix.org", 7777)

    while True:
        #Send next stuff
        if(len(sendlist)):
            pkg = sendlist.pop()
            s.mysend(pkg[0], pkg[1])
        
        try:
            recv = s.myreceive()
            print(recv)
        except:
            #Nuthin
            pass
        
        time.sleep(0.05)

def pslogin(user, password):
    t = threading.Thread(target=network_loop)
    t.start()

    message = msg_preauth()
    message.append(0xB9) #PS id
    pkg = makepacket(message)
    sendlist.insert(0, pkg)

#Start dialog
print("Welcome to Planeshift text client! Login here")

loginname = None
loginpassword = None

if(len(sys.argv) > 1):
    loginname = sys.argv[1]
else:
    loginname = input("Username: ")

if(len(sys.argv) > 2):
    loginpassword = sys.argv[2]
else:
    loginpassword = getpass.getpass("Password: ")

pslogin(loginname, loginpassword)
