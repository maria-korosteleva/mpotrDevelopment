#!/usr/bin/env python

def receivedMessage(account, sender, message, conversation, flags):
    print conversation,", ",  sender, "said:", message

# Import libraries
import dbus, gobject
from dbus.mainloop.glib import DBusGMainLoop
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SessionBus()

# Add receivedMessage signal handler
bus.add_signal_receiver(receivedMessage, dbus_interface="im.pidgin.purple.PurpleInterface", signal_name="ReceivedImMsg")

# set purple object
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
#conv_name = raw_input("Choose your buddy name: ")
conv_name = "mkorostel"
conv = purple.PurpleConversationNew(1, account, conv_name + "@qip.ru")

# example of writing to chat
message = raw_input("Write something: ")
#message = "Hi!"
purple.PurpleConvImSend(purple.PurpleConvIm(conv), message)

for convers in purple.PurpleGetIms():
    purple.PurpleConvImSend(purple.PurpleConvIm(convers), "Ignore.")

# main loop
loop = gobject.MainLoop()
loop.run()