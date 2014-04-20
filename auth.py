#!/usr/bin/env python

############################ Our favorite class ############################

class Round:
    sended = 0
    recieved = 0


class mpOTRContext:
    # chat
    init_mess_count = 0   # initialisation -- Channel Establishment
    usernameList = []
    nonceList = []
    r_1 = Round()
    r_2 = Round()
    r_3 = Round()
    r_4 = Round()
    # and so
    def __init__(self, chat):
        self.chat = chat
        self.members_count = len(purple.PurpleConvChatGetUsers(chat))
        print self.members_count, " members in chat are online"
        # init arrays of needed size
        for user in purple.PurpleConvChatGetUsers(chat):
            self.nonceList.append("")
            self.usernameList.append(purple.PurpleConvChatCbGetName(user))
        self.usernameList.sort()

################################ Functions #################################

len_sid_random = 13

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
                    print "IDSKE finished"
            elif (mess_splitted[1] == "ERR"):
                print "mpOTR ERROR: ", mess_splitted[2]
        
       #### Round 1 processing ####
#
# Generate keys and send message to chat
#
def sendRound_1():
    global context, crypto
    # generate nonce for session key
    context.k_i = crypto.getSomeNonce(len_sid_random)
    k_i_hashed = base64.b64encode(crypto.hash(context.k_i, len(context.k_i)))
    # Generate Long-term keys
    keys = ""
    crypto.generateKeys(c_char_p(keys), c_char_p(keys))
    # Generate ephemeral keys
    
    # Send message 
    purple.PurpleConvChatSend(chat, "mpOTR:A_R1:"+k_i_hashed+";"+y_i_enc+";"+S_i_enc)

#
# Process reciever Round 1 message
#
def processRound_1():
    global context, crypto
    


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
    i = 0
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

