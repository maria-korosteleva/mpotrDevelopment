#!/usr/bin/env python

############################ Our favorite class ############################

class MsgRecord:
    def __init__(self, sender,  mId, parents, decrypted, raw):
        self.resended = 0 # ONlY FOR DEMONSTRATION PURPOSE
        self.sender = sender
        self.msgId = mId
        self.parents = parents
        self.txt = decrypted
        self.raw = raw

class Round:
    sended = 0
    recieved = 0
class Communicate:
    messNum = 0 # Number of text messages sended to the chat
    frontier = []
    lostMsg = []
    undelivered = []
    delivered = []


class mpOTRContext:
    # chat
    usernameList = []
    # Initiation info
    init_mess_count = 0   # initialisation -- Channel Establishment
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
    len_msg_id_random = 8
    comm = Communicate()
    # Shutdown phase info
    sdwnStarted = 0
    sdwnTranscriptCompleted = 0
    sdwn = Round()
    sdwnConf = Round()
    keyPair = Round()
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
                    print "IDSKE finished successfully"
                    # set the lost messages requests
                    gobject.timeout_add(10000, requestLostMsg) # request every 3 sec
                    sendOneTextMess()
            elif (mess_splitted[1] == "TEXT"):
                processText(sender, mess_splitted[2])
            elif (mess_splitted[1] == "LostMsgReq"):
                processRequestLostMsg(sender, mess_splitted[2])
            elif (mess_splitted[1] == "Sdwn"):
                context.sdwnStarted = 1
                processShutdownInit(sender, mess_splitted[2])
                if not context.sdwn.sended:
                    sendShutdown()
                    context.sdwn.sended = 1
                if (context.sdwn.recieved == context.members_count): 
                    requestLostMsg() # in case some are losted
                if (context.sdwn.recieved == context.members_count) and context.sdwnTranscriptCompleted: 
                    # Shutdown initiation finished
                    sendShutdownConfirm()
                    context.sdwnConf.sended = 1
            elif (mess_splitted[1] == "SdwnConf"):
                processShutdownConf(sender, mess_splitted[2])
                if not context.sdwnConf.sended:
                    sendShutdownConfirm()
                    context.sdwnConf.sended = 1
                if (context.sdwnConf.recieved == context.members_count): 
                    purple.PurpleConvChatSend(context.chat, "mpOTR:KeyPair:" + context.myEphKeys)
                    context.keyPair.sended = 1
            elif (mess_splitted[1] == "KeyPair"):
                print sender, "'s ephemeral keypair is:", mess_splitted[2]
                context.keyPair.recieved += 1
                if not context.keyPair.sended:
                    purple.PurpleConvChatSend(context.chat, "mpOTR:KeyPair:" + context.myEphKeys)
                    context.keyPair.sended = 1
                if (context.keyPair.recieved == context.members_count): 
                    # Shutdown is finished
                    print "Your conversation is finished (properly)"
            elif (mess_splitted[1] == "ERR"):
                print "mpOTR ERROR: ", mess_splitted[2]
        


############## Shutdown phase #####################
#
# Send shutdown initiation message
#
def sendShutdown():
    global context, crypto, purple 
    ## Add the OldBlue info here
    time.sleep(5)
    msgId = crypto.getSomeNonce(c_int(context.len_msg_id_random))
    finMsg = "mpOTR:Sdwn:" + context.sid + ";" + msgId
    if len(context.comm.frontier) > 0:
        for i in range(0, len(context.comm.frontier)): # Adding msg's parents
            finMsg += ";" + context.comm.frontier[i]
    finMsg += ";"
    sign = crypto.sign(c_char_p(finMsg), c_char_p(context.myEphKeys))
    purple.PurpleConvChatSend(context.chat, finMsg + sign)
    context.sdwn.sended = 1

#
# Send message to confirm shutdown
#
def sendShutdownConfirm():
    global context, crypto, purple
    time.sleep(context.myNum+3)
    #time.sleep(2)
    finMsg = "mpOTR:SdwnConf:" + context.sid + ";"
    sign = crypto.sign(c_char_p(finMsg), c_char_p(context.myEphKeys))
    purple.PurpleConvChatSend(context.chat, finMsg + sign)

#
# Check the signature and the sid of the shutdown initiation message
# Message format: sid;messageId;parent1;...;parentN;signature
# List of parents may be empty
#
def processShutdownInit(sender, msg):
    global context, crypto, purple   
    mess_splitted = msg.split(";")
    count = len(mess_splitted)
    tmp = "mpOTR:Sdwn:" + mess_splitted[0]  # verify signature
    for i in range(1, count-1):
        tmp += ";" + mess_splitted[i]
    tmp += ";"
    # Verify the signature
    for i in range(0, context.members_count):
        if context.usernameList[i] == sender:
            err = crypto.verifySign(c_char_p(tmp), c_char_p(mess_splitted[count-1]), c_char_p(context.ephPubKeys[i]))
            if (err != 0):
                purple.PurpleConvChatSend(context.chat, "mpOTR:ERR:Error Process Init Shutdown at verifing signature from "+sender)
                return
    #Check the sid
    if (mess_splitted[0] != context.sid):
        purple.PurpleConvChatSend(context.chat, "mpOTR:ERR:"+sender+" sended wrong SessionID while Shutdown initiation")
        return
    clearLostMsg(mess_splitted[1]) 
    tmp = ""
    #if count-1 > 2
    for i in range(2, count-1):
        tmp += mess_splitted[i] + ";"  # Careful! It ends with empty piece
    checkLostedParents(tmp) # check parents
    context.sdwn.recieved +=1
    deliver()

    # check transcript completeness
    if context.sdwnStarted and len(context.comm.lostMsg) == 0 and len(context.comm.undelivered) == 0:
        context.sdwnTranscriptCompleted = 1
#
# Check the signature and the sid of the shutdown confirmation message
#
def processShutdownConf(sender, msg):
    global context, crypto, purple
    mess_splitted = msg.split(";", 2)
    # Verify the signature
    for i in range(0, context.members_count):
        if context.usernameList[i] == sender:
            err = crypto.verifySign(c_char_p("mpOTR:SdwnConf" + mess_splitted[0] + ";"), c_char_p(mess_splitted[1]), c_char_p(context.ephPubKeys[i]))
            if (err != 0):
                purple.PurpleConvChatSend(context.chat, "mpOTR:ERR:Error Processing Shutdown Confirmation at verifing signature from "+sender)
                return
            context.sdwnConf.recieved +=1



############## Communication phase #####################
#
# Send some message to the chat
#
def sendOneTextMess():
    global context
    if context.comm.messNum == 0:
        sendEncOldBlueMess("Hi1!")
    elif context.comm.messNum == 1:
        sendEncOldBlueMess("hi2!")
    elif context.comm.messNum == 2:
        sendEncOldBlueMess("hi3!")
    elif context.comm.messNum == 3:
        sendEncOldBlueMess("hi4!")
    elif context.comm.messNum == 4:
        sendEncOldBlueMess("hi5!")
    elif context.comm.messNum == 5:
        sendEncOldBlueMess("hi6!")
    elif not context.sdwn.sended :
        context.sdwn.sended = 1
        sendShutdown()
    context.comm.messNum += 1

#
# Pack the message and send it 
#
def sendEncOldBlueMess(message):
    global context, crypto, purple 
    msgEnc = crypto.encrypt(c_char_p(message), c_char_p(context.sessionKey))
    #msgEnc = message # for DEBUG
    msgId = crypto.getSomeNonce(c_int(context.len_msg_id_random))
    finMsg = "mpOTR:TEXT:" + context.myUsername + ";" + context.sid + ";" + msgEnc + ";" + msgId
    parents = ""
    if len(context.comm.frontier) > 0:
        for i in range(0, len(context.comm.frontier)): # Adding msg's parents
            parents += ";" + context.comm.frontier[i]
    finMsg += parents + ";"
    sign = crypto.sign(c_char_p(finMsg), c_char_p(context.myEphKeys))
    if context.comm.messNum == 1 and context.myNum == 1:
    #if 0:
        # Deliver only to client2 -- aka Losted message for everyone except client2
        print "Xe-Xe ;)"
        clearLostMsg(msgId) 
        tmp = ""
        checkLostedParents(parents) # check parents
        finMsg += sign
        context.comm.undelivered.append(MsgRecord(context.myUsername, msgId, parents,  msgEnc, finMsg))
        deliver() 
 
        # Piece for shutdown phase
        if context.sdwnStarted and len(context.comm.lostMsg) == 0 and len(context.comm.undelivered) == 0:
            context.sdwnTranscriptCompleted = 1
            if (context.sdwn.recieved == context.members_count): 
                # Shutdown initiation finished
                sendShutdownConfirm()
                context.sdwnConf.sended = 1

        context.comm.messNum += 1
        sendOneTextMess()
        context.comm.messNum -= 1 # Getting back the order of messNum

    else:
        # Ordinary situation
        purple.PurpleConvChatSend(context.chat, finMsg + sign)

#
# Process the incoming Lost Msg request
#
def processRequestLostMsg(sender, message):
    global context, purple
    time.sleep(2 + context.myNum)
    #time.sleep(2)
    mess_splitted = message.split(";")
    #print "We have LostMsg request from ", sender, " asking ", mess_splitted[0]
    # verify signature
    for i in range(0, context.members_count):
        if context.usernameList[i] == sender:
            err = crypto.verifySign(c_char_p("mpOTR:LostMsgReq" + mess_splitted[0] + ";"), c_char_p(mess_splitted[1]), c_char_p(context.ephPubKeys[i]))
            if (err != 0):
                purple.PurpleConvChatSend(context.chat, "mpOTR:ERR:Error LostMsgRequestProcessing: at verifing signature from "+sender)
                return
    messageId = mess_splitted[0]
    for i in range(0, len(context.comm.delivered)):
        if context.comm.delivered[i].msgId == messageId:
            purple.PurpleConvChatSend(context.chat, context.comm.delivered[i].raw) 
            #print "Sending ", messageId, " as requested"
            return
    for i in range(0, len(context.comm.undelivered)):
        if context.comm.undelivered[i].msgId == messageId:
            purple.PurpleConvChatSend(context.chat, context.comm.undelivered[i].raw) 
            #print "Sending ", messageId, " as requested"
            return
    # not found
#
# Request all messages from LostMsg buffer
#
def requestLostMsg():
    global crypto, context, purple
    time.sleep(1 + context.myNum)
    #time.sleep(2)
    if len(context.comm.lostMsg) > 0:
        for i in range(0, len(context.comm.lostMsg)):
            #print "I'm ", context.myNum, " requesting ", len(context.comm.lostMsg), "times message ", context.comm.lostMsg[i] 
            msg = "mpOTR:LostMsgReq:" + context.comm.lostMsg[i] + ";"
            sign = crypto.sign(c_char_p(msg), c_char_p(context.myEphKeys))
            toSend = msg + sign
            purple.PurpleConvChatSend(context.chat, toSend)
            #print "Sended"
    #else:
        #print "LostMsg Empty"
    if context.sdwnStarted:
        return 0
    else:
        return 1
#
# if message with msgId is in the LostMsg buffer -- erase this record, the message is recieved
#
def clearLostMsg(msgId):
    global context
    try:
        context.comm.lostMsg.remove(msgId)
        #print "Cleared ", msgId
    except BaseException:
        pass # its ok if the element is not found
#
# Check is some messages from the list of messages' IDs is losted
# Returns 0 if all parents are delivered
#
def checkLostedParents(idList):
    global crypto, context
    ids = idList.split(";")
    res = 0
    for j in range(0, len(ids)):
        if ids[j] != "":  # Some pieces may be empty
            messageId = ids[j]
            flag = 0
            for i in range(0, len(context.comm.delivered)):
                if context.comm.delivered[i].msgId == messageId:
                    flag = 1
                    break
            if flag: 
                continue
            res = -1
            for i in range(0, len(context.comm.undelivered)):
                if context.comm.undelivered[i].msgId == messageId:
                    flag = 1
                    break
            if flag: 
                continue
            for i in range(0, len(context.comm.lostMsg)):
                if context.comm.lostMsg[i] == messageId:
                    flag = 1
                    break
            if flag: 
                continue
            # Not found
            context.comm.lostMsg.append(messageId) 
    return res
#
# Remove ids from frontier buffer if they are in it
#
def clearFrontier(msgIds):
    global context
    ids = msgIds.split(";")
    res = 0
    for i in range(0, len(ids)):
        if ids[i] != "":  # Some pieces may be empty
            try:
                context.comm.frontier.remove(ids[i])
            except BaseException:
                pass # its ok if the element is not found so do some useless stuff
#
# Deliver messages that can be delivered
#
def deliver():
    global crypto, context
    delivered_smth = 1
    while(delivered_smth != 0):
        delivered_smth = 0
        for i in range(0, len(context.comm.undelivered)):
            if (checkLostedParents(context.comm.undelivered[i].parents) == 0): # message can be delivered
                delivered_smth = 1
                # remove parents from frontier
                clearFrontier(context.comm.undelivered[i].parents)
                # add messageId to frontier
                context.comm.frontier.append(context.comm.undelivered[i].msgId)
                # add to Delivered
                context.comm.delivered.append(context.comm.undelivered[i])
                # Didplay! *Finally*
                msgDec = crypto.decrypt(c_char_p(context.comm.undelivered[i].txt), c_char_p(context.sessionKey))
                print context.comm.undelivered[i].sender, " said:", msgDec
                # remove from undelivered
                del context.comm.undelivered[i]
                break

#
# Process recieved Text (Communication phase) message
# message has format: origSenderName;sid;EncryptedText;messageId;parent1;..;parentN;Signature
# Message may have no parents
#
def processText(sender, message):
    global context, crypto, purple
    mess_splitted = message.split(";")
    count = len(mess_splitted)
    tmp = "mpOTR:TEXT:" + mess_splitted[0]  # verify signature
    for i in range(1, count-1):
        tmp += ";" + mess_splitted[i]
    tmp += ";"
    for i in range(0, context.members_count):
        if context.usernameList[i] == mess_splitted[0]: # we need original sender
            err = crypto.verifySign(c_char_p(tmp), c_char_p(mess_splitted[count-1]), c_char_p(context.ephPubKeys[i]))
            if (err != 0):
                purple.PurpleConvChatSend(context.chat, "mpOTR:ERR:Error at verifying signature from "+sender)
                #print "mpOTR:ERR:Error processing Text: at verifying signature from ", sender
                return
    if (mess_splitted[1] != context.sid): # check sessionID
        purple.PurpleConvChatSend(context.chat, "mpOTR:ERR:"+sender+" sended wrong SessionID while processing Text")
        return
    msgId = mess_splitted[3] 
    clearLostMsg(msgId) 
    # Do not process message that is already here
    for i in range(0, len(context.comm.delivered)):
        if context.comm.delivered[i].msgId == msgId:
            return
    for i in range(0, len(context.comm.undelivered)):
        if context.comm.undelivered[i].msgId == msgId:
            return

    tmp = ""
    #if count-1 > 4
    for i in range(4, count-1):
        tmp += mess_splitted[i] + ";"  # Careful! It ends with empty piece
    checkLostedParents(tmp) # check parents
    #print "Recieved ", mess_splitted[2], " from ", mess_splitted[0]
    #print "recieved message with id ", mess_splitted[3], "with  parents ", tmp
    origSender = mess_splitted[0]
    context.comm.undelivered.append(MsgRecord(origSender, mess_splitted[3], tmp,  mess_splitted[2], "mpOTR:TEXT:" + message))
    deliver() 

    # Piece for shutdown phase

    if context.sdwnStarted and len(context.comm.lostMsg) == 0 and len(context.comm.undelivered) == 0:
        context.sdwnTranscriptCompleted = 1
        if (context.sdwn.recieved == context.members_count): 
            # Shutdown initiation finished
            sendShutdownConfirm()
            context.sdwnConf.sended = 1

    #print sender, "said:", msgDec 
    time.sleep(5)
    sendOneTextMess()


############### Authentication Round 1 processing ####
#
# Generate keys and send message to chat
#
def sendRound_1():
    global context, crypto, purple
    # generate nonce for session key
    context.k_i = crypto.getSomeNonce(c_int(context.len_sid_random))
    k_i_hashed = crypto.hash(c_char_p(context.k_i), c_int(len(context.k_i)))
    
    # Generate Long-term keys
    ### like this: *Well, this may not be exactly long-term key. Whatever.*
    context.myPrivKey = crypto.getSomeNonce(c_int(context.len_authNonce_random))
    context.myPubKey = crypto.exponent(c_char_p("2"), c_char_p(context.myPrivKey))
    
    if 1:
        # Read from file Ephemeral keys
        file = open(join(split(__file__)[0],"ephkey"+context.myUsername+".txt"), 'r')
        context.myEphKeys = file.read() # this is a keypair -- public and private keys
        file.close()
        file = open(join(split(__file__)[0],"ephPubkey"+context.myUsername+".txt"), 'r')
        context.myEphPubKey = file.read()
        file.close()
    else:
        # Generate Ephemeral keys
        print "start Key generation for ", context.myUsername
        context.myEphKeys = crypto.generateKeys()
        file = open(join(split(__file__)[0],"ephkey"+context.myUsername+".txt"), 'w')
        file.write(context.myEphKeys)
        file.close()
        context.myEphPubKey = crypto.getPubPrivKey(c_char_p(context.myEphKeys), c_char_p("public-key"))
        file = open(join(split(__file__)[0],"ephPubkey"+context.myUsername+".txt"), 'w')
        file.write(context.myEphPubKey)
        file.close()

    # Send message 
    purple.PurpleConvChatSend(context.chat, "mpOTR:A_R1:"+k_i_hashed+";"+ context.myPubKey+";"+context.myEphPubKey)

#
# Process recieved Round 1 message
#
def processRound_1(sender, message):
    global context
    # Split the message
    mess_splitted = message.split(";", 2)
    # Add to buffers
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
    # hash it to get SID
    context.sid = crypto.hash(c_char_p(sid_raw), c_int(len(sid_raw))) # is the length ok? #FIX
    # generate auth nonce
    context.r_i = crypto.getSomeNonce(c_int(context.len_authNonce_random))
    # get exponent of auth nonce
    context.exp_r_i = crypto.exponent( c_char_p("2"), c_char_p(context.r_i))
    # Send message 
    purple.PurpleConvChatSend(context.chat, "mpOTR:A_R2:"+context.sid+";"+ context.exp_r_i)

#
# Process recieved Round 2 message
#
def processRound_2(sender, message):
    global context, purple
    # Split the message
    mess_splitted = message.split(";", 1)
    # Add to buffers
    ## get list of buddies and find sender's number
    for i in range(0, context.members_count):
        if context.usernameList[i] == sender:
            # Check if all the sid's are the same
            if context.sid != mess_splitted[0]:
                purple.PurpleConvChatSend(context.chat, "mpOTR:ERR:"+ sender +" sended a wrong SessionID")    
            else:
                ## Add exponent of authNonce to list
                context.expAuthNonce[i] = mess_splitted[1]
                context.r_2.recieved +=1

############### Authentication Round 3 processing ####
#
# Generate t's and send message to chat
#
def sendRound_3():
    global context, crypto, purple
    # find my number
    myNum = -1;
    for i in range(0, context.members_count):
        if context.usernameList[i] == context.myUsername:
            myNum = i
            break
    if myNum == -1:
        print "Something is wrong with the username"
    context.myNum = myNum
    print "My Number is ", context.myNum
    ind_left = context.members_count-1 if (myNum == 0) else myNum-1
    ind_right = 0 if (myNum == context.members_count-1) else myNum+1
    
    # generate t_left
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
    purple.PurpleConvChatSend(context.chat, "mpOTR:A_R3:"+ xoredK_i +";"+ context.myBigT)

#
# Process recieved Round 3 message
#
def processRound_3(sender, message):
    global context
    # Split the message
    mess_splitted = message.split(";", 1)
    # Add to buffers
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
    global context, crypto, purple
    error = 0
    # decrypt Nonces
    i = context.myNum
    t_R = context.my_t_right
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

        if hash_check != context.hashedNonceList[i]:
            error = 1
            purple.PurpleConvChatSend(context.chat, "mpOTR:ERR:"+ "Error at verifing nonces -- bad hash")
            return
    # verify bigTs
    T_ver = context.bigTList[0]
    for i in range(1, context.members_count):
        T_ver = crypto.xor(c_char_p(T_ver), c_char_p(context.bigTList[i]))
    if T_ver != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=":  ##### MAY BE BAD CONDITION -- THE HASH LENGTH MAY CHANGE
        error = 2;
        purple.PurpleConvChatSend(context.chat, "mpOTR:ERR:"+ "Error -- big T's xsum is not zero, it is " + T_ver)

    if error == 0: # Everithing is allright so far
        
        # Compute session key
        nonces = ""
        for i in range(0, context.members_count):
            nonces += context.nonceList[i]
        context.sessionKey = crypto.hash(c_char_p(nonces), c_int(len(nonces)))
        
        sconf_tmp = ""
        for i in range(0, context.members_count):
            sconf_tmp += context.lPubKeys[i]+","+context.nonceList[i]+","+context.ephPubKeys[i]
        context.sconf = crypto.hash(c_char_p(sconf_tmp), c_int(len(sconf_tmp)))
        c_i_raw = context.sid + context.sconf 
        context.c_i = crypto.hash(c_char_p(c_i_raw), c_int(len(c_i_raw)))
        # Compute auth check info -- d_i
        context.d_i = crypto.minus(c_char_p(context.r_i), c_char_p(crypto.mult(c_char_p(context.c_i), c_char_p(context.myPrivKey), c_char('q'))))
        context.sig = crypto.sign(c_char_p(context.c_i), c_char_p(context.myEphKeys))
        purple.PurpleConvChatSend(context.chat, "mpOTR:A_R4:"+ context.d_i +";"+ context.sig)

#
# Process recieved Round 4 message
#
def processRound_4(sender, message):
    global context, crypto, purple
    # Split the message
    mess_splitted = message.split(";", 1)
    for i in range(0, context.members_count):
        if context.usernameList[i] == sender:
            context.r_4.recieved +=1
            error = 0
            # verify recieved d_i (mess_splitted[0]) with z_i
            exp_1 = crypto.exponent(c_char_p("2"), c_char_p(mess_splitted[0]))
            exp_2 = crypto.exponent(c_char_p(context.lPubKeys[i]), c_char_p(context.c_i))
            d_check = crypto.mult(c_char_p(exp_1), c_char_p(exp_2), c_char('p'))
            if d_check != context.expAuthNonce[i]:
                #print "mpOTR:ERR: Error at verifing auth info from ", sender, " -- bad exponent"
                purple.PurpleConvChatSend(context.chat, "mpOTR:ERR:Error at verifing auth info -- bad exponent")
                return
            # verify recieved signature (mess_splitted[1]) with author's ephPubKey
            err = crypto.verifySign(c_char_p(context.c_i), c_char_p(mess_splitted[1]), c_char_p(context.ephPubKeys[i]))
            if err:
                #print "mpOTR:ERR: Error at verifing signature of c_i from ", sender
                purple.PurpleConvChatSend(context.chat, "mpOTR:ERR:Error at verifing signature of c_i")
                return

#
# Generate and send nonce to chat
# Additional function for debuging needs
#
def sendNonce(chat):
    global context, crypto, purple
    nonce_raw = crypto.getSomeNonce(c_int(context.len_sid_random))
    nonce_enc = nonce_raw
    purple.PurpleConvChatSend(context.chat, "mpOTR:SID:"+nonce_enc)

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
import dbus, gobject, ctypes, time
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
#purple.PurpleConvChatSetNick(context.chat, nicknames[account_number-1])

# example of writing to chat
#message = raw_input("Write something: ")
#purple.PurpleConvChatSend(context.chat, message)

#for convers in purple.PurpleGetChats():
#    purple.PurpleConvChatSend(purple.PurpleConvChat(convers), "Ignore.")


### len(purple.PurpleConvChatGetUsers(context.chat))

