#!/usr/bin/env python

# "chat" and "conv_chat", "sid" -- those we are using in this turn
sid = ""
#
# Handle Recieved message
#
nonce_sended = 0
init_mess_count = 0
def receivedMessage(account, sender, message, conversation, flags):
    global conv_chat, chat, nonce_sended, init_mess_count
    if conversation == conv_chat:
        print sender, "said:", message
        if message == "I'm here":
            init_mess_count += 1
        else:
            mess_splitted = message.split(":", 2)
            if len(mess_splitted) == 3:
                if (mess_splitted[0] == "mpOTR") and (mess_splitted[1] == "SID"):
                    processNonce(sender, mess_splitted[2])
                    if not nonce_sended:
                        sendNonce(chat)
                        nonce_sended = 1
        if (init_mess_count == 3) and not nonce_sended:
            sendNonce(chat)
            nonce_sended = 1

#
# Generate and send nonce to chat
#
def sendNonce(chat):
    global crypto
    crypto.getSomeNonce.restype = c_char_p #return type
    nonce_raw = crypto.getSomeNonce(13)
    nonce_enc = base64.b64encode(nonce_raw)
    purple.PurpleConvChatSend(chat, "mpOTR:SID:"+nonce_enc)

#
# process reciever nonce
#
nonceList = []
usersList = []
count_added = 0
def processNonce(sender, nonce):
    global nonceList, usersList, chat, count_added, sid
    print "processing..."
    ## first use -> init
    if nonceList == []:
        for user in purple.PurpleConvChatGetUsers(chat):
            nonceList.append("")
            usersList.append(purple.PurpleConvChatCbGetName(user))
        usersList.sort()
    nonce_raw = base64.b64decode(nonce)
    ## get list of buddies and find sender's number
    i = 0
    for i in range(0, len(usersList)):
        if usersList[i] == sender:
            print "found... ", i, " ", nonce
            ## add to list using this number
            nonceList[i] = nonce_raw
            count_added +=1
        i += 1
    if count_added == len(usersList):
        print "finishing..."
        # finishing -- ready to get sid
        # concate all strings
        sid_raw = ""
        for i in range(0, count_added):
            sid_raw += nonceList[i]
        print sid_raw, len(sid_raw)
        # hash it to get SID
        sid = crypto.hash(c_char_p(sid_raw), len(sid_raw))
        print sid


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

# Say that you are in
purple.PurpleConvChatSend(chat, "I'm here")

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

