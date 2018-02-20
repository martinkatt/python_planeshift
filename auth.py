import socket
import struct
import sys
import getpass
import threading
import time
import queue
import hashlib

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
    splitmsgdef = [
        "I",
        "s",
        "s",
        "s",
        "s",
        "s",
        "H",
        "H",
        "s",
        "s",
        "s"]
    msgdef = "<BH"
    msglen = 8
    msgheaderlen = 3
    msgpayload = [msgtype,
        msglen,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None]
    curappendpos = 0

    def append(self, content):
        self.msgpayload[self.curappendpos + 2] = content
        
        adddef = self.splitmsgdef[self.curappendpos]

        #We need to figure out how long the text is
        isdynstring = adddef == "s"
        
        if(isdynstring):
            self.msgdef += str(len(content))
            
        self.msgdef += adddef
        
        if(isdynstring):
            self.msglen = struct.calcsize(self.msgdef) - self.msgheaderlen
        
        self.curappendpos += 1

messagedict = {
    4: msg_preautapprove
}

msgcounter = 1

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
    global msgcounter
    packet = struct.pack(pktdef, msgcounter, 0, pktlen, pktlen, 0x01)
    packet += message;
    reallen = struct.calcsize(pktdef) + pktlen
    msgcounter += 1

    return packet

sendlist = queue.Queue()
recvlist = queue.Queue()

def network_loop():
    s = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("planeshift.teamix.org", 7777))

    while True:
        #Send next package
        #TODO check if socket is busy
        #TODO make the sendlist atomic or something
        #to prevent fiddling with by other threads 
        if not sendlist.empty():
            pkg = sendlist.get()

            s.send(pkg)
            sendlist.task_done()
        
        #See if we got response
        #TODO check if socket is done sending
        try:
            recv = s.recv(2048)

            print(recv)

            #What did we get?
            if(len(recv) > 15):
                #Parse the packet
                pktdef = "<IIIHBBH"
                
                headers = struct.unpack(pktdef, recv[:18])
                
                messageobj = messagedict[headers[6]]()
                
                completedef = pktdef + messageobj.msgdef[3:]

                wholemessage = struct.unpack(completedef, recv)
                
                recvlist.put(wholemessage)
            else:
                print("ACK")
                #It is an ACK
                pass
        except:
            #Nuthin
            pass
        
        time.sleep(0.05)

def on_preautapprove(message, user, password):
    #Then we need to put the stuff in an auth message
    #it should be username, password with the response we got
    #from preauthapproved
    authmsg = msg_auth()
    authmsg.append(0xB9)
    authmsg.append(bytes(user + "\0", 'utf-8'))

    #Password to sha256
    encodedpw = hashlib.sha256()
    encodedpw.update(password.encode('utf-8'))
    pwhex = encodedpw.hexdigest()
    #Append the stuff we got from the message
    compoundpw = str(message[3]) + ":" + pwhex
    #Guess what, encode it again
    finalencode = hashlib.sha256()
    finalencode.update(compoundpw.encode('utf-8'))

    authmsg.append(bytes(str(finalencode.hexdigest()) + "\0", 'utf-8'))

    #Next thing is our OS
    authmsg.append(bytes("U\0", 'utf-8'))
    #Graphics card
    authmsg.append(bytes("RoxorFore\0", 'utf-8'))
    #GFX card version
    authmsg.append(bytes("3L173\0", 'utf-8'))
    #OS major
    authmsg.append(13)
    #OS minor
    authmsg.append(37)
    #Empty PW string
    authmsg.append(bytes("\0", 'utf-8'))
    #OS platform
    authmsg.append(bytes("Python OS\0", 'utf-8'))
    #Machine
    authmsg.append(bytes("x86_64\0", 'utf-8'))

    print(authmsg.msgdef)

    pkg = makepacket(authmsg)
    print(pkg)
    sendlist.put(pkg)

#On login
def pslogin(user, password):
    #Start networking
    #Wait until we got a preauthapproved message
    #there need to be a better way to construct events
    #that can be called without waiting
    t = threading.Thread(target=network_loop)
    t.start()

    #Send preauth event
    message = msg_preauth()
    message.append(0xB9) #PS id
    pkg = makepacket(message)
    sendlist.put(pkg)

    while True:
        if not recvlist.empty():
            on_preautapprove(recvlist.get(), user, password)
            recvlist.task_done()

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
