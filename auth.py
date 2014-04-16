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
#    nonce_sended = 0
#    count_added = 0
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
# Handle Recieved message
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
                 ######### working ######            
                    sendNonce(context.chat)
                    context.r_1.sended = 1
            elif (mess_splitted[1] == "SID"):
                processNonce(sender, mess_splitted[2])
                if not context.r_1.sended:
                   sendNonce(context.chat)
                   context.r_1.sended = 1
        

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

