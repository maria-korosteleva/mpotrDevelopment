#!/usr/bin/env python

############################ Our favorite class ############################

class Round:
    sended = 0
    recieved = 0


class mpOTRContext:
    # chat
    init_mess_count = 0   # initialisation -- Channel Establishment
    usernameList = []
    hashedNonceList = []
    lPubKeys = []
    lPubKeysLen = []
    ephPubKeys = []
    ephPubKeysLen = []
    sid = ""
    expAuthNonce = []
    xoredNonceList = []
    bigTList = []
#    nonceList = []
    myKeys = ""
    myPubKey = ""
    myEphKeys = ""
    myEphPubKey = ""
    r_1 = Round()
    r_2 = Round()
    r_3 = Round()
    r_4 = Round()
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
            self.bigTList.append("")
            self.expAuthNonce.append("")
            self.hashedNonceList.append("")
            self.lPubKeys.append("")
            self.lPubKeysLen.append(0)
            self.ephPubKeys.append("")
            self.ephPubKeysLen.append(0)
            self.usernameList.append(purple.PurpleConvChatCbGetName(user))
        self.usernameList.sort()

################################ Functions #################################

len_sid_random = 13
len_authNonce_random = 4 # May be we should make it larger, 
                         # but then we need to do something
                         # with module at the exponent function in crypto 

#
# Handle Recieved message -- big switch
#
def receivedMessage(account, sender, message, conversation, flags):
    global context
    if conversation == purple.PurpleConvChatGetConversation(context.chat):
        print sender, "said:", message
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
            elif (mess_splitted[1] == "ERR"):
                print "mpOTR ERROR: ", mess_splitted[2]
        
############### Round 1 processing ####
#
# Generate keys and send message to chat
#
def sendRound_1():
    global context, crypto
    # generate nonce for session key
    context.k_i = crypto.getSomeNonce(len_sid_random)
    k_i_hashed = base64.b64encode(crypto.hash(context.k_i, len(context.k_i)))
    
    # Generate Long-term keys
    context.myKeys = crypto.generateKeys()
    context.myPubKey = crypto.getPubPrivKey(c_char_p(context.myKeys), c_char_p("public-key"))
    # print "Hey Hey Key ", context.myKeys
    
    # Generate Ephemeral keys
    # context.myEphKeys = crypto.generateKeys()
    # context.myEphPubKey = crypto.getPubPrivKey(c_char_p(context.myEphKeys), c_char_p("public-key"))
    
    # Send message 
    purple.PurpleConvChatSend(chat, "mpOTR:A_R1:"+k_i_hashed+";"+ context.myPubKey+";"+context.myEphPubKey)

#
# Process recieved Round 1 message
#
def processRound_1(sender, message):
    global context, crypto
    # Split the message
    mess_splitted = message.split(";", 2)
    # Add to buffers
    ## get list of buddies and find sender's number
    for i in range(0, context.members_count):
        if context.usernameList[i] == sender:
            ## add to list using this number
            context.hashedNonceList[i] = mess_splitted[0]
            context.lPubKeys[i] = mess_splitted[1]
            # context.lPubKeysLen[i] = int(mess_splitted[2])
            context.ephPubKeys[i] = mess_splitted[2]
            # context.ephPubKeysLen[i] = int(mess_splitted[4])
            context.r_1.recieved +=1


############### Round 2 processing ####
#
# Generate sid, auth info and send message to chat
#
def sendRound_2():
    global context, crypto
    # generate SID
    sid_raw = ""
    for i in range(0, context.r_1.recieved):
        sid_raw += base64.b64decode(context.hashedNonceList[i])
    # hash it to get SID
    context.sid = base64.b64encode(crypto.hash(c_char_p(sid_raw), len(sid_raw)))
    # generate auth nonce
    context.r_i = crypto.getSomeNonce(len_authNonce_random)
    # get exponent of auth nonce
    context.exp_r_i = base64.b64encode(crypto.exponent("2", context.r_i))
    # Send message 
    purple.PurpleConvChatSend(chat, "mpOTR:A_R2:"+context.sid+";"+ context.exp_r_i)

#
# Process recieved Round 2 message
#
def processRound_2(sender, message):
    global context, crypto
    # Split the message
    mess_splitted = message.split(";", 1)
    # Add to buffers
    ## get list of buddies and find sender's number
    for i in range(0, context.members_count):
        if context.usernameList[i] == sender:
            # Check if all the sid's are the same
            if context.sid != mess_splitted[0]:
                #print sender, " sended a wrong SessionID"
                purple.PurpleConvChatSend(chat, "mpOTR:ERR:"+ sender +" sended a wrong SessionID")    
            else:
                ## Add exponent of authNonce to list
                context.expAuthNonce[i] = mess_splitted[1]
                context.r_2.recieved +=1

############### Round 3 processing ####
#
# Generate t's and send message to chat
#
def sendRound_3():
    global context, crypto
    # find my number
    myNum = -1;
    for i in range(0, context.members_count):
        if context.usernameList[i] == context.myUsername:
            ## Add recived info to lists
            myNum = i
    if myNum == -1:
        print "Something wrong with the username"

    # generate t_left
    context.my_t_left = ""
    # generate t_right
    context.my_t_right = ""
    # generate big_T
    context.myBigT = ""
    #context.myBigT = context.my_t_left XOR context.my_t_right
    xoredK_i = ""
    #xoredK_i = context.k_i XOR context.my_t_right
    # Send message 
    purple.PurpleConvChatSend(chat, "mpOTR:A_R3:"+ xoredK_i +";"+ context.myBigT)

#
# Process recieved Round 3 message
#
def processRound_3(sender, message):
    global context, crypto
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

############### Round 4 processing ####
#
# Generate t's and send message to chat
#
def sendRound_4():
    global context, crypto
    error = 0
    # decrypt Nonces
    # verify nonce's hashes
    # verify bigTs
    if error:
        purple.PurpleConvChatSend(chat, "mpOTR:ERR:"+ "verification error at step one")    
    else:
        # Compute session key
        # Compute Session confirmation info
        # Compute temp key -- c_i
        # Compute auth check info -- d_i
        context.d_i = ""
        # sign key with myEphPrivKey
        context.sig = ""
        # Send message 
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
            error = 0
            # verify recieved d_i (mess_splitted[0]) with z_i
            # verify recieved signature (mess_splitted[1]) with author's ephPubKey
            if error:
                purple.PurpleConvChatSend(chat, "mpOTR:ERR:"+ "verification error at authorisation step")    
            else:
                context.r_4.recieved +=1
#
# Generate and send nonce to chat
#
def sendNonce(chat):
    global crypto
    nonce_raw = crypto.getSomeNonce(len_sid_random)
    nonce_enc = base64.b64encode(nonce_raw)
    purple.PurpleConvChatSend(chat, "mpOTR:SID:"+nonce_enc)

#
# process reciever nonce
#
def processNonce(sender, nonce):
    global context
    nonce_raw = base64.b64decode(nonce)
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
        sid = crypto.hash(c_char_p(sid_raw), len(sid_raw))
        print "This Session's ID is ", base64.b64encode(sid)


####################### Main program #############################

# Import libraries
import dbus, gobject, ctypes
import base64
from ctypes import *
from dbus.mainloop.glib import DBusGMainLoop
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()
crypto = ctypes.CDLL('/root/mpotrDevelopment/c_func_mpotr.so')
crypto.initLibgcrypt()
crypto.getSomeNonce.restype = c_char_p #return type
crypto.hash.restype = c_char_p #return type
crypto.generateKeys.restype = c_char_p #return type
crypto.getPubPrivKey.restype = c_char_p #return type
crypto.exponent.restype = c_char_p #return type

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
    if ch_acc == account:
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

