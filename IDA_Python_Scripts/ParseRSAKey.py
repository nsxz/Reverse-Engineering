#---------------------------------------------------------------------
#    Simple IDA script to find RSA public keys and parse
#
#---------------------------------------------------------------------
import os
import idaapi
from idautils import *

RSA_public_sig = '06 ? 00 00 00 ? 00 00 52 53 41 31'

cur_addr = MinEA()
MaxAddr = MaxEA()
while cur_addr < MaxAddr:
    addr = idc.FindBinary(cur_addr, SEARCH_DOWN, RSA_public_sig)
    if addr != idc.BADADDR:
        if hex(Byte(addr+5)) == '0xa4':
            print '%s' % hex(Byte(addr+5))
            aiKeyAlg = 'CALG_RSA_KEYX'
        elif hex(Byte(addr+5)) == '0x24':
            aiKeyAlg = 'CALG_RSA_SIGN'
        else:
            aiKeyAlg = 'UnKnow'
        print 'Find RSA public key at %s : aiKeyAlg=> %s ; keyLength=> %s = %d bit' % (hex(addr), aiKeyAlg, hex(Dword(addr+12)), Dword(addr+12))
        break
    else:
        print "Can't Find RSA public key information.."

print'Key scan complete.\n'
