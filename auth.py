#!/usr/bin/env python

############################ Our favorite class ############################

class Round:
    sended = 0
    recieved = 0
class Communicate:
    messNum = 0 # Number of text messages sended to the chat


class mpOTRContext:
    # chat
    init_mess_count = 0   # initialisation -- Channel Establishment
    usernameList = []
    # AKE info 
    len_sid_random = 13
    len_authNonce_random = 0 # Means that the random number will be modulo prime number q 
    hashedNonceList = []
    lPubKeys = []
    ephPubKeys = []
    sid = ""
    expAuthNonce = []
    xoredNonceList = []
    bigTList = []
    nonceList = []
    myPrivKey = ""
    myPubKey = ""
    myEphKeys = ""
    myEphPubKey = ""
    r_1 = Round()
    r_2 = Round()
    r_3 = Round()
    r_4 = Round()
    # Comm phase info
    comm = Communicate()
    # and so
    def __init__(self, chat):
        self.chat = chat
        user = purple.PurpleConversationGetAccount(purple.PurpleConvChatGetConversation(chat))
        self.myUsername = purple.PurpleAccountGetUsername(user).split("@")[0]
        self.members_count = len(purple.PurpleConvChatGetUsers(chat))
        print self.members_count, " members in chat are online"
        # init arrays of needed size
        for user in purple.PurpleConvChatGetUsers(chat):
            self.xoredNonceList.append("")
            self.nonceList.append("")
            self.bigTList.append("")
            self.expAuthNonce.append("")
            self.hashedNonceList.append("")
            self.lPubKeys.append("")
            self.ephPubKeys.append("")
            self.usernameList.append(purple.PurpleConvChatCbGetName(user))
        self.usernameList.sort()

################################ Functions #################################

#
# Handle Recieved message -- big switch
#
def receivedMessage(account, sender, message, conversation, flags):
    global context
    if conversation == purple.PurpleConvChatGetConversation(context.chat):
        #print sender, "said:", message # Commented for DEBUGing purpose 
        mess_splitted = message.split(":", 2)
        if (len(mess_splitted) == 3) and (mess_splitted[0] == "mpOTR"):
            if mess_splitted[1] == "Init":
                context.init_mess_count += 1
                if (context.init_mess_count == context.members_count) and not context.r_1.sended:         
                    sendRound_1()
                    context.r_1.sended = 1
            elif (mess_splitted[1] == "A_R1"):
                processRound_1(sender, mess_splitted[2])
                if not context.r_1.sended:
                    sendRound_1()
                    context.r_1.sended = 1
                if ((context.r_1.recieved == context.members_count)
                and not context.r_2.sended): 
                # Round finished
                    sendRound_2()
                    context.r_2.sended = 1
            elif (mess_splitted[1] == "A_R2"):
                processRound_2(sender, mess_splitted[2])
                if not context.r_2.sended:
                    sendRound_2()
                    context.r_2.sended = 1
                if ((context.r_2.recieved == context.members_count)
                and not context.r_3.sended): 
                # Round finished
                    sendRound_3()
                    context.r_3.sended = 1
            elif (mess_splitted[1] == "A_R3"):
                processRound_3(sender, mess_splitted[2])
                if not context.r_3.sended:
                    sendRound_3()
                    context.r_3.sended = 1
                if ((context.r_3.recieved == context.members_count)
                and not context.r_4.sended):
                # Round finished
                    sendRound_4()
                    context.r_4.sended = 1
            elif (mess_splitted[1] == "A_R4"):
                processRound_4(sender, mess_splitted[2])
                if not context.r_4.sended:
                    sendRound_4()
                    context.r_4.sended = 1
                if (context.r_4.recieved == context.members_count): 
                # Round finished
                    print "Success! IDSKE finished!"
                    sendOneTextMess()
            elif (mess_splitted[1] == "TEXT"):
                processText(sender, mess_splitted[2])
            elif (mess_splitted[1] == "ERR"):
                print "mpOTR ERROR: ", mess_splitted[2]
        

############## Communication phase #####################
#
# Send some message to the chat
#
def sendOneTextMess():
    global context
    if context.comm.messNum == 0:
        sendEncOldBlueMess("Hi1!")
    elif context.com.messNum == 1:
        sendEncOldBlueMess("Hi2!")
    context.comm.messNum += 1

#
# Pack the message and send it 
#
def sendEncOldBlueMess(message):
    global context, crypto    
    msgEnc = crypto.encrypt(c_char_p(message), c_char_p(context.sessionKey))
    sign = crypto.sign(c_char_p(msgEnc), c_char_p(context.myEphKeys))
    #print "Testing encryption ", res
    purple.PurpleConvChatSend(chat, "mpOTR:TEXT:" + msgEnc + ";" + sign)
    #res = crypto.decrypt(c_char_p(res), c_char_p(context.sessionKey))
    #print "Testing decryption ", res

#
# Process recieved Text (Communication phase) message
#
def processText(sender, message):
    global context
    print sender, "said:", message  
    # Split the message
    #mess_splitted = message.split(";", 2)
    # Add to buffers
    ## get list of buddies and find sender's number
    #for i in range(0, context.members_count):
    #    if context.usernameList[i] == sender:
    #        ## add to list using this number
    #        context.hashedNonceList[i] = mess_splitted[0]
    #        context.lPubKeys[i] = mess_splitted[1]
    #        context.ephPubKeys[i] = mess_splitted[2]
    #        context.r_1.recieved +=1



############### Authentication Round 1 processing ####
#
# Generate keys and send message to chat
#
def sendRound_1():
    global context, crypto
    # generate nonce for session key
    context.k_i = crypto.getSomeNonce(c_int(context.len_sid_random))
    k_i_hashed = crypto.hash(c_char_p(context.k_i), c_int(len(context.k_i)))
    
    # Generate Long-term keys
    ### like this: *Well, this may not be exactly long-term key. Whatever.*
    context.myPrivKey = crypto.getSomeNonce(c_int(context.len_authNonce_random))
    context.myPubKey = crypto.exponent(c_char_p("2"), c_char_p(context.myPrivKey))
    
    # Generate/Read from file Ephemeral keys
    #context.myEphKeys = crypto.generateKeys()
    file = open(join(split(__file__)[0],"ephkey"+context.myUsername+".txt"), 'r')
    context.myEphKeys = file.read() # this is a keypair -- public and private keys

    # for signing with private key only Run this in the morning, please!
    #context.myEphKeys = crypto.getPubPrivKey(c_char_p(context.myEphKeys), c_char_p("private-key"))
    
    #file.write(context.myEphKeys)
    file.close()
    #context.myEphPubKey = crypto.getPubPrivKey(c_char_p(context.myEphKeys), c_char_p("public-key"))
    file = open(join(split(__file__)[0],"ephPubkey"+context.myUsername+".txt"), 'r')
    context.myEphPubKey = file.read()
    #file.write(context.myEphPubKey)
    file.close()
    
    # Send message 
    purple.PurpleConvChatSend(chat, "mpOTR:A_R1:"+k_i_hashed+";"+ context.myPubKey+";"+context.myEphPubKey)

#
# Process recieved Round 1 message
#
def processRound_1(sender, message):
    global context
    # Split the message
    mess_splitted = message.split(";", 2)
    # Add to buffers
    ## get list of buddies and find sender's number
    for i in range(0, context.members_count):
        if context.usernameList[i] == sender:
            ## add to list using this number
            context.hashedNonceList[i] = mess_splitted[0]
            context.lPubKeys[i] = mess_splitted[1]
            context.ephPubKeys[i] = mess_splitted[2]
            context.r_1.recieved +=1


############### Authentication Round 2 processing ####
#
# Generate sid, auth info and send message to chat
#
def sendRound_2():
    global context, crypto
    # generate SID
    sid_raw = ""
    for i in range(0, context.r_1.recieved):
        sid_raw += context.hashedNonceList[i]
        #sid_raw += base64.b64decode(context.hashedNonceList[i])
    # hash it to get SID
    context.sid = crypto.hash(c_char_p(sid_raw), c_int(len(sid_raw))) # is the length ok? #FIX
    # generate auth nonce
    context.r_i = crypto.getSomeNonce(c_int(context.len_authNonce_random))
    # get exponent of auth nonce
    #print "Get exponent of auth nonce"
    context.exp_r_i = crypto.exponent( c_char_p("2"), c_char_p(context.r_i))
    # Send message 
    purple.PurpleConvChatSend(chat, "mpOTR:A_R2:"+context.sid+";"+ context.exp_r_i)

#
# Process recieved Round 2 message
#
def processRound_2(sender, message):
    global context
    # Split the message
    mess_splitted = message.split(";", 1)
    # Add to buffers
    ## get list of buddies and find sender's number
    for i in range(0, context.members_count):
        if context.usernameList[i] == sender:
            # Check if all the sid's are the same
            if context.sid != mess_splitted[0]:
                purple.PurpleConvChatSend(chat, "mpOTR:ERR:"+ sender +" sended a wrong SessionID")    
                print sender, " sended a wrong SID"
            else:
                ## Add exponent of authNonce to list
                context.expAuthNonce[i] = mess_splitted[1]
                context.r_2.recieved +=1

############### Authentication Round 3 processing ####
#
# Generate t's and send message to chat
#
def sendRound_3():
    global context, crypto
    # find my number
    myNum = -1;
    for i in range(0, context.members_count):
        if context.usernameList[i] == context.myUsername:
            myNum = i
            break
    if myNum == -1:
        print "Something is wrong with the username"
    context.myNum = myNum
    ind_left = context.members_count-1 if (myNum == 0) else myNum-1
    ind_right = 0 if (myNum == context.members_count-1) else myNum+1
    
    # generate t_left
    #print ind_left, "'s (left) long pub key is ", context.lPubKeys[ind_left]
    #print myNum, " mine is ", context.lPubKeys[myNum] 
    #print ind_right, "'s (right) long pub key is ", context.lPubKeys[ind_right]
    t_left_raw = crypto.exponent(c_char_p(context.lPubKeys[ind_left]), c_char_p(context.myPrivKey))
    context.my_t_left = crypto.hash(c_char_p(t_left_raw), c_int(len(t_left_raw)))  
    # generate t_right
    t_right_raw = crypto.exponent(c_char_p(context.lPubKeys[ind_right]), c_char_p(context.myPrivKey))
    context.my_t_right = crypto.hash(c_char_p(t_right_raw), c_int(len(t_right_raw)))
    # generate big_T
    context.myBigT = crypto.xor(c_char_p(context.my_t_left), c_char_p(context.my_t_right))
    # Xor k_i
    xoredK_i = crypto.xor(c_char_p(context.k_i), c_char_p(context.my_t_right))
    
    # Send message 
    purple.PurpleConvChatSend(chat, "mpOTR:A_R3:"+ xoredK_i +";"+ context.myBigT)

#
# Process recieved Round 3 message
#
def processRound_3(sender, message):
    global context
    # Split the message
    mess_splitted = message.split(";", 1)
    # Add to buffers
    ## get list of buddies and find sender's number
    for i in range(0, context.members_count):
        if context.usernameList[i] == sender:
            ## Add recived info to lists
            context.xoredNonceList[i] = mess_splitted[0]
            context.bigTList[i] = mess_splitted[1]
            context.r_3.recieved +=1

############### Authentication Round 4 processing ####
#
# Generate t's and send message to chat
#
def sendRound_4():
    global context, crypto
    error = 0
    # decrypt Nonces
    i = context.myNum
    t_R = context.my_t_right
    #print "I'm ", i   #, ", tr is ", t_R
    #print "I'm ", i, ", tL is ", context.my_t_left
    #print "I am ", context.myNum, ", my ki is ", context.k_i
    while(1):
        
        if (i == context.members_count-1):
            i = -1
        t_R = crypto.xor(c_char_p(context.bigTList[i+1]), c_char_p(t_R))
        context.nonceList[i+1] = crypto.xor(c_char_p(context.xoredNonceList[i+1]), c_char_p(t_R))
        i = i+1
        if i == context.myNum:
            break
    # verify nonce's hashes
    for i in range(0, context.members_count):
        hash_check = crypto.hash(c_char_p(context.nonceList[i]), c_int(len(context.nonceList[i])))
        #print i, " hash check ", hash_check
        #print i, " hash original ", context.hashedNonceList[i]
        #print i, " ki check ", context.nonceList[i]

        if hash_check != context.hashedNonceList[i]:
            error = 1
            purple.PurpleConvChatSend(chat, "mpOTR:ERR:"+ "Error at verifing nonces -- bad hash")
            break
    # verify bigTs
    T_ver = context.bigTList[0]
    for i in range(1, context.members_count):
        T_ver = crypto.xor(c_char_p(T_ver), c_char_p(context.bigTList[i]))
    if T_ver != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=":  ##### MAY BE BAD CONDITION -- THE HASH LENGTH MAY CHANGE
        error = 2;
        purple.PurpleConvChatSend(chat, "mpOTR:ERR:"+ "Error -- big T's xsum is not zero, it is " + T_ver)

    if error == 0: # Everithing is allright so far
        
        # Compute session key
        nonces = ""
        for i in range(0, context.members_count):
            nonces += context.nonceList[i]
        context.sessionKey = crypto.hash(c_char_p(nonces), c_int(len(nonces)))
        
        # Compute Session confirmation info
        #print "Calculating sconf"
        sconf_tmp = ""
        for i in range(0, context.members_count):
            sconf_tmp += context.lPubKeys[i]+","+context.nonceList[i]+","+context.ephPubKeys[i]
        context.sconf = crypto.hash(c_char_p(sconf_tmp), c_int(len(sconf_tmp)))
        # Compute temp key -- c_i
        c_i_raw = context.sid + context.sconf 
        context.c_i = crypto.hash(c_char_p(c_i_raw), c_int(len(c_i_raw)))
        # Compute auth check info -- d_i
        #print "Calculating d_i"
        context.d_i = crypto.minus(c_char_p(context.r_i), c_char_p(crypto.mult(c_char_p(context.c_i), c_char_p(context.myPrivKey), c_char('q'))))
        # sign key with myEphPrivKey
        context.sig = crypto.sign(c_char_p(context.c_i), c_char_p(context.myEphKeys))
        # Sender of the message sended a wrong SID 

        purple.PurpleConvChatSend(chat, "mpOTR:A_R4:"+ context.d_i +";"+ context.sig)

#
# Process recieved Round 4 message
#
def processRound_4(sender, message):
    global context, crypto
    # Split the message
    mess_splitted = message.split(";", 1)
    ## get list of buddies and find sender's number
    for i in range(0, context.members_count):
        if context.usernameList[i] == sender:
            context.r_4.recieved +=1
            error = 0
            # verify recieved d_i (mess_splitted[0]) with z_i
            # print "Check started: exponent 2 to d_i for ", i
            exp_1 = crypto.exponent(c_char_p("2"), c_char_p(mess_splitted[0]))
            # print "Exponent their public key to c_i (h(sid and sconf))"
            exp_2 = crypto.exponent(c_char_p(context.lPubKeys[i]), c_char_p(context.c_i))
            d_check = crypto.mult(c_char_p(exp_1), c_char_p(exp_2), c_char('p'))
            if d_check != context.expAuthNonce[i]:
                print "mpOTR:ERR: Error at verifing auth info from ", sender, " -- bad exponent"
                purple.PurpleConvChatSend(chat, "mpOTR:ERR:Error at verifing auth info -- bad exponent")
                break
            #print "d_i is correct!"
            # verify recieved signature (mess_splitted[1]) with author's ephPubKey
            err = crypto.verifySign(c_char_p(context.c_i), c_char_p(mess_splitted[1]), c_char_p(context.ephPubKeys[i]))
            if err:
                print "mpOTR:ERR: Error at verifing signature of c_i from ", sender
                purple.PurpleConvChatSend(chat, "mpOTR:ERR:Error at verifing signature of c_i")
                break
            #print "Signature was verified successfully!"

#
# Generate and send nonce to chat
# Additional function for debuging needs
#
def sendNonce(chat):
    global context, crypto
    nonce_raw = crypto.getSomeNonce(c_int(context.len_sid_random))
    nonce_enc = nonce_raw
    purple.PurpleConvChatSend(chat, "mpOTR:SID:"+nonce_enc)

#
# process reciever nonce
# Additional function for debuging needs
#
def processNonce(sender, nonce):
    global context
    nonce_raw = nonce
    #nonce_raw = base64.b64decode(nonce)
    ## get list of buddies and find sender's number
    for i in range(0, context.members_count):
        if context.usernameList[i] == sender:
            ## add to list using this number
            context.nonceList[i] = nonce_raw
            context.r_1.recieved +=1
    if context.r_1.recieved == context.members_count: # finishing
        # concate all strings
        sid_raw = ""
        for i in range(0, context.r_1.recieved):
            sid_raw += context.nonceList[i]
#        print base64.b64encode(sid_raw), len(sid_raw)
        # hash it to get SID
        sid = crypto.hash(c_char_p(sid_raw), c_int(len(sid_raw)))
        print "This Session's ID is ", sid


####################### Main Main program #############################

# Import libraries
import dbus, gobject, ctypes
import base64
from ctypes import * 
from dbus.mainloop.glib import DBusGMainLoop
DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
from os.path import join, split
crypto = ctypes.CDLL(join(split(__file__)[0],'./c_func_mpotr.so'))
crypto.initLibgcrypt()
crypto.getSomeNonce.restype = c_char_p #return type
crypto.hash.restype = c_char_p #return type
crypto.generateKeys.restype = c_char_p #return type
crypto.getPubPrivKey.restype = c_char_p #return type
crypto.exponent.restype = c_char_p #return type
crypto.xor.restype = c_char_p #return type
crypto.minus.restype = c_char_p
crypto.mult.restype = c_char_p
crypto.sign.restype = c_char_p
crypto.verifySign.restype = c_int
crypto.encrypt.restype = c_char_p
crypto.decrypt.restype = c_char_p

###!!!!!!!!!#
#crypto.findq()
#crypto.expCheck()
#crypto.round4Check()
#crypto.pk_example()
#crypto.enc_example()

# Add receivedMessage signal handler
bus.add_signal_receiver(receivedMessage, dbus_interface="im.pidgin.purple.PurpleInterface", signal_name="ReceivedChatMsg")

# set purple object
obj = bus.get_object("im.pidgin.purple.PurpleService", "/im/pidgin/purple/PurpleObject")
purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")

# Choose one of three XMPP accounts
i = 1
for acc in purple.PurpleAccountsGetAllActive():
    if purple.PurpleAccountGetProtocolId(acc) == "prpl-jabber":
        print i, purple.PurpleAccountGetUsername(acc)
        i += 1

# Get account to work with
account_number = int(raw_input("Choose the account (number): "))
account = purple.PurpleAccountsGetAllActive()[account_number-1]
print "\nYour account is ", purple.PurpleAccountGetUsername(account)

# Fing needed chat
for conv_chat in purple.PurpleGetChats():
    ch_acc = purple.PurpleConversationGetAccount(conv_chat)
    if ch_acc == account:    # FIX NEEDED: potentially fails with several chats
         chat = purple.PurpleConvChat(conv_chat)
         
# Create the context
context = mpOTRContext(chat)

# Say that you are in
purple.PurpleConvChatSend(chat, "mpOTR:Init:I'm here")

# main loop
loop = gobject.MainLoop()
loop.run()

############################ Some trash pieces ####################################

# Nicknames
#nicknames = ["Alice", "Bob", "Charlie"]
#print "Your nick is ", nicknames[account_number-1]
#purple.PurpleConvChatSetNick(chat, nicknames[account_number-1])

# example of writing to chat
#message = raw_input("Write something: ")
#purple.PurpleConvChatSend(chat, message)

#for convers in purple.PurpleGetChats():
#    purple.PurpleConvChatSend(purple.PurpleConvChat(convers), "Ignore.")


### len(purple.PurpleConvChatGetUsers(chat))

