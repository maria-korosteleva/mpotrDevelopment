#!/usr/bin/env python

# "chat" and "conv_chat" -- those we are using in this turn

nonce_sended = 0
init_mess_count = 0

#
# Handle Recieved message
#
def receivedMessage(account, sender, message, conversation, flags):
    global conv_chat, chat, nonce_sended, init_mess_count
    if conversation == conv_chat:
        print sender, "said:", message
    if message == "I'm here":
        init_mess_count += 1
    if 0: #### Message is nonce ###:
        ######### proccess it #######
        if not nonce_sended:
            sendNonce(chat)
            nonce_sended = 1
    elif (init_mess_count == 3) and not nonce_sended:
        sendNonce(chat)
        nonce_sended = 1

#
# Generate and send nonce to chat
#
def sendNonce(chat):
    global crypto
    print "sending..."
    crypto.getSomeNonce.restype = c_char_p #return type
    nonce = crypto.getSomeNonce(13)
    purple.PurpleConvChatSend(chat, "mpOTR:SID:"+nonce)

#
# process reciever nonce
#
nonceList = []
def processNonce(nonce):
    global nonceList
    print "processing..."


####################### Main program #############################

# Import libraries
import dbus, gobject, ctypes
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

