__author__ = 'Crobject'
from idautils import *
from idc import *

import os
def searchForHex(start,bytes):
    return FindBinary(start ,SEARCH_DOWN,' '.join(hex(x) for x in bytes))

def isOPStatic(opName):
    if opName == 'bl' or opName == 'lis' or opName == 'b' or opName == 'ble' or opName == 'bne' or opName == 'blt' or opName == 'addi':
        return False
    else:
        return True
def isHexUnique(addr, str):
    addr = searchForHex(addr,str)
    return searchForHex(addr + 4,str) == BADADDR
def findUniqueBytes(function):
    byteList = []
    offset = 0
    for i in range(function, FindFuncEnd(function), 4):
        if isOPStatic(GetMnem(i)):
            for b in range(4):
                byteList.append(Byte(i + b))
            if isHexUnique(0, byteList):
                #print('Unique Hex String {0} {1}'.format(GetFunctionName(function), ' '.join(hex(x) for x in byteList)))
                return ' '.join(hex(x) for x in byteList)
        else:
            byteList = []
        offset += 1
def getBytesOffset(address, bytes):
    return FindBinary(address ,SEARCH_DOWN,bytes) - address
def doAddImport(ea, name, ord):
    importList.append(name)
    return True

function_map = {}
functionList = []
importList = []
importNum = idaapi.get_import_module_qty()
for i in range(importNum):
     idaapi.enum_import_names(i, doAddImport)

ea = ScreenEA()
#open the idc file and write the initial byte signagure code
file = open(os.getcwd() + '\\{0} - {1}.idc'.format(GetInputFile().split('.')[0], GetInputFileMD5()), 'w')
print(file.name)
filedata = 'I2luY2x1ZGUgPGlkYy5pZGM+DQpzdGF0aWMgRmluZEZ1bmN0aW9uKGJpbmFyeSwgb2Zmc2V0KXsNCglhdXRvIGN1cnJlbnRBZGRyZXNzLCBsYXN0QWRkcmVzczsNCglmb3IoY3VycmVudEFkZHJlc3M9MDsgY3VycmVudEFkZHJlc3MgIT0gQkFEQUREUjsgY3VycmVudEFkZHJlc3M9Y3VycmVudEFkZHJlc3MrNCkNCgl7DQoJY3VycmVudEFkZHJlc3MgPSBGaW5kQmluYXJ5KGN1cnJlbnRBZGRyZXNzLCBTRUFSQ0hfRE9XTiwgYmluYXJ5KTsNCglyZXR1cm4gY3VycmVudEFkZHJlc3MgLSBvZmZzZXQ7DQoJfQ0KfQ0Kc3RhdGljIEFkZEZ1bmN0aW9uKG5hbWUsIGJpbmFyeSwgb2Zmc2V0KXsNCglhdXRvIGFkZHJlc3MgPSBGaW5kRnVuY3Rpb24oYmluYXJ5LCBvZmZzZXQpOw0KCWF1dG8gbGVuZ3RoID0gRmluZEZ1bmNFbmQoYWRkcmVzcykgLSBhZGRyZXNzOw0KCU1ha2VGdW5jdGlvbihhZGRyZXNzLCBhZGRyZXNzICsgbGVuZ3RoKTsNCglpZihNYWtlTmFtZUV4KGFkZHJlc3MsIG5hbWUsIFNOX05PQ0hFQ0t8U05fTk9XQVJOKSAhPSAxKQ0KCQlNYWtlTmFtZUV4KGFkZHJlc3MsIG5hbWUsIDApOw0KCU1lc3NhZ2UoIiVzID0gMHglWFxuIiwgbmFtZSwgYWRkcmVzcyk7DQp9DQpzdGF0aWMgbWFpbigpew0K'.decode('base64')
file.write(filedata)
#find only functions that are renamed by the user
for function_ea in Functions(SegStart(ea), SegEnd(ea)):
    f_name = GetFunctionName(function_ea)
    if (not f_name.startswith('sub_') and not f_name.startswith('__rest') and not f_name.startswith('__save')) and not f_name in importList:
        print('{0} Added'.format(f_name))
        functionList.append(function_ea)

#loop through functions and find unique codes
for i in range(len(functionList )):
    function_ea = functionList[i]
    f_name = GetFunctionName(function_ea)
    uBytes = findUniqueBytes(function_ea)
    offset = getBytesOffset(function_ea,uBytes)
    if not uBytes:
        print('Unable to find {0}'.format(f_name))
        continue
    print('{3}/{4} {0} = {1} @ {2}'.format(f_name, uBytes, offset, i, len(functionList)))
    file.write('\tAddFunction("{0}", "{1}", {2});\n'.format(f_name,uBytes, offset))
file.write('}')
file.close()