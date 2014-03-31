#!/usr/bin/env python

def receivedMessage(account, sender, message, conversation, flags):
    print conversation,", ",  sender, "said:", message

# Import libraries
import dbus, gobject
from dbus.mainloop.glib import DBusGMainLoop
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()

# Add receivedMessage signal handler
bus.add_signal_receiver(receivedMessage, dbus_interface="im.pidgin.purple.PurpleInterface", signal_name="ReceivedChatMsg")

# set purple object
bus = dbus.SessionBus()
obj = bus.get_object("im.pidgin.purple.PurpleService", "/im/pidgin/purple/PurpleObject")
purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")

# Printing XMPP accounts
for acc in purple.PurpleAccountsGetAllActive():
    if purple.PurpleAccountGetProtocolId(acc) == "prpl-jabber":
        print purple.PurpleAccountGetUsername(acc) 

# Get account to work with
#account_name = raw_input("Choose the account you wish to use today: ")
account_name = "korosteleva2@gmail.com/"
account = purple.PurpleAccountsFind(account_name, "prpl-jabber")

# Create new chat with user's defined name
conv_name = raw_input("Choose the desired conversation name: ")
conv = purple.PurpleConversationNew(2, account, conv_name + "@conference.qip.ru")
purple.PurpleConversationSetName(conv, conv_name) 	
chat = purple.PurpleConversationGetChatData(conv)

# Add new user to chat
#nickname = raw_input("Choose your desired nickname: ")
nickname = "korosteleva"
purple.PurpleConversationSetAccount(conv, account) 
purple.PurpleConvChatAddUser(chat, account_name, "New user in chat", 4, 1)	
purple.PurpleConvChatSetNick(chat, nickname)

# Set chat topic Do we need this?
#topic = raw_input("Set the chat topic: ")
topic = "topic"
purple.PurpleConvChatSetTopic(chat, nickname, topic)

# example of writing to chat
#message = raw_input("Write something: ")
message = "Hi!"
purple.PurpleConvChatWrite(chat, nickname, message, 0, 0)

for convers in purple.PurpleGetChats():
    purple.PurpleConvChatSend(purple.PurpleConvChat(convers), "Ignore.")

# main loop
loop = gobject.MainLoop()
loop.run()

