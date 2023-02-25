'''
Python3 ACS-ACR122U-Tool
'''
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.ATR import ATR
from smartcard.CardType import AnyCardType
import sys
import json
import base64


if len(sys.argv) < 2:
    print("usage: nfcTool.py <command>\nList of available commands: help, mute, unmute, getuid, info, loadkey, read, firmver")
    sys.exit()

r = readers()
if len(r) < 1:
    print("error: No readers available!")
    sys.exit()

# print("Available readers: ", r)


reader = r[0]

availableReaders = str(r)
currentReader = str(reader)

# print("Using: ", reader)

connection = reader.createConnection()
connection.connect()

# detect command
cmd = sys.argv[1]

if cmd == "help":
    print("usage: python nfctool.py <command>\nList of available commands: help, mute, unmute, getuid")
    print("Before executing command, make sure that a card is being tagged on the reader.")
    print("\thelp\tShow this help page")
    print("\tmute\tDisable beep sound when card is tagged.")
    print("\tunmute\tEnable beep sound when card is tagged.")
    print("\tgetuid\tPrint UID of the tagged card.")
    print("\tinfo\tPrint card type and available protocols.")
    print("\tloadkey <key>\tLoad key <key> (6byte hexstring) for auth.")
    print("\tread\tRead all sectors  with loaded key.")
    print("\tfirmver\tPrint the firmware version of the reader.")
    sys.exit()

cmdMap = {
    "mute": [0xFF, 0x00, 0x52, 0x00, 0x00],
    "unmute": [0xFF, 0x00, 0x52, 0xFF, 0x00],
    "getuid": [0xFF, 0xCA, 0x00, 0x00, 0x00],
    "firmver": [0xFF, 0x00, 0x48, 0x00, 0x00],
}

COMMAND = cmdMap.get(cmd, cmd)


def printJsonResponse(response):
    print(json.dumps(response))
    sys.exit()


response = {
    'availableReaders': availableReaders,
    'reader': currentReader,
}

# send command
if type(COMMAND) == list:
    data, sw1, sw2 = connection.transmit(COMMAND)
    if cmd == "firmver":
        response['version'] = ''.join(chr(i)
                                      for i in data)+chr(sw1)+chr(sw2)

    else:
        response[cmd] = toHexString(data)

    if (sw1, sw2) == (0x90, 0x0):
        response['status'] = 'Success'

    elif (sw1, sw2) == (0x63, 0x0):
        response['status'] = 'Failed'

    # response
    printJsonResponse(response)

elif type(COMMAND) == str:
    if COMMAND == "info":

        # print("###Tag Info###")
        atr = ATR(connection.getATR())
        hb = toHexString(atr.getHistoricalBytes())
        cardname = hb[-17:-12]
        cardnameMap = {
            "00 01": "MIFARE Classic 1K",
            "00 02": "MIFARE Classic 4K",
            "00 03": "MIFARE Ultralight",
            "00 26": "MIFARE Mini",
            "F0 04": "Topaz and Jewel",
            "F0 11": "FeliCa 212K",
            "F0 11": "FeliCa 424K"
        }
        name = cardnameMap.get(cardname, "unknown")

        response['cardName'] = name
        response['isT0Supported'] = atr.isT0Supported()
        response['isT1Supported'] = atr.isT1Supported()
        response['isT15Supported'] = atr.isT15Supported()

        # response
        printJsonResponse(response)

    elif COMMAND == "loadkey":
        if (len(sys.argv) < 3):
            response['status'] = 'Failed'
            response['errorList'] = [
                "usage: python nfctool.py loadkey <key>",
                "ex) python nfctool.py loadkey FFFFFFFFFFFF"
            ]
            # response
            printJsonResponse(response)

        COMMAND = [0xFF, 0x82, 0x00, 0x00, 0x06]
        key = [sys.argv[2][0:2], sys.argv[2][2:4], sys.argv[2][4:6],
               sys.argv[2][6:8], sys.argv[2][8:10], sys.argv[2][10:12]]
        for i in range(6):
            key[i] = int(key[i], 16)
        COMMAND.extend(key)

        data, sw1, sw2 = connection.transmit(COMMAND)

        response['statusWords'] = str(sw1)+' '+str(sw2)

        if (sw1, sw2) == (0x90, 0x0):

            response['message'] = 'Key is loaded successfully to key #0.'
            response['status'] = 'Success'

        elif (sw1, sw2) == (0x63, 0x0):

            response['message'] = 'Failed to load key.'
            response['status'] = 'Failed'

        # response
        printJsonResponse(response)

    elif COMMAND == "read":
        # decrypt first block of sector with key. if succeed, sector is unlocked
        # if other sector is unlocked, previous sector is locked

        dataString = ''

        # blockLoop = sys.argv[2]

        shouldLoop = True

        for blockLoop in range(1, 15):
            COMMAND = [0xFF, 0x86, 0x00, 0x00, 0x05,
                       0x01, 0x00, int(blockLoop)*4, 0x60, 0x00]

            data, sw1, sw2 = connection.transmit(COMMAND)
            if (sw1, sw2) == (0x90, 0x0):

                response['StatusLoopSector'+str(blockLoop)] = 'Decryption sector' + \
                    str(blockLoop) + " using key #0 as Key A successful."

            elif (sw1, sw2) == (0x63, 0x0):

                response['StatusLoopSector'+str(blockLoop)] = 'Decryption sector' + \
                    str(blockLoop) + " failed. Trying as Key B"

                COMMAND = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01,
                           0x00, int(blockLoop)*4, 0x61, 0x00]

                data, sw1, sw2 = connection.transmit(COMMAND)
                if (sw1, sw2) == (0x90, 0x0):

                    response['StatusLoopSector'+str(blockLoop)+'bis'] = 'Decryption sector' + \
                        str(blockLoop) + " using key #0 as Key B successful."

                elif (sw1, sw2) == (0x63, 0x0):

                    response['status'] = 'Failed'

                    # response
                    printJsonResponse(response)

            for block in range(int(blockLoop)*4, int(blockLoop)*4+4):
                COMMAND = [0xFF, 0xB0, 0x00]
                COMMAND.append(block)
                COMMAND.append(16)

                data, sw1, sw2 = connection.transmit(COMMAND)

                dataLoop = ''

                for dataKey in data:
                    charLoop = chr(dataKey)
                    if dataKey == 0x00:
                        shouldLoop = False
                        continue
                    if dataKey == 0xFE:
                        # end
                        shouldLoop = False
                        break
                    if dataKey == 0x03:
                        charLoop = 'NDEF'
                        shouldLoop = True

                    if dataKey == 0xFD:
                        charLoop = 'PROPR'

                    dataLoop += charLoop

                dataString += dataLoop

                if shouldLoop == False:
                    break

            # if shouldLoop == False:
            #    break

            if (sw1, sw2) == (0x90, 0x0):

                response['status'] = 'Success'

            elif (sw1, sw2) == (0x63, 0x0):
                response['status'] = 'Failed'

        response['data'] = dataString

        # print(dataString)
        # response
        printJsonResponse(response)

    else:
        response['status'] = 'Failed'
        response['message'] = "Undefined command: " + \
            cmd + "\nUse \"help\" command for command list."

        printJsonResponse(response)
