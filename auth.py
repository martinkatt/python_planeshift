import socket
import struct
import sys
import getpass
import threading
import time
import queue

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

messagedict = {
    4: msg_preautapprove
}

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
            s.send(pkg[0])
            sendlist.task_done()
        
        #See if we got response
        #TODO check if socket is done sending
        try:
            recv = s.recv(2048)
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

def on_preautapprove(message):
    print("hullo")
    #Then we need to put the stuff in an auth message
    #it should be username, password with the response we got
    #from preauthapproved

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
            on_preautapprove(recvlist.get())
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
