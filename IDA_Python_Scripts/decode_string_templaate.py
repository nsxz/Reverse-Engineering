import idc
import idautils
import idaapi

begin_position = 0x10011157 # This value must be changed
begin_position_copy = begin_position

 

def decrypt(data):
  length = len(data)
  c = 0
  o = ""
  while (c < length) and (ord(data[c]) != 0x00):
    o += chr(ord(data[c]) ^ 0x7F)
    c += 1
  return o


def find_function_arg(addr):
    min_addr = addr - 10
    while True:
        addr = idc.PrevHead(addr)
        if addr > min_addr:
            if GetMnem(addr) == "mov" and "ecx" in GetOpnd(addr, 0) and  GetOpType(addr, 1) != 1 and GetOpType(addr, 1) != 4 and GetOpType(addr, 1) != 3 :
                #print "%s => %s => %s" % (hex(addr), GetOpnd(addr, 1), hex(GetOperandValue(addr, 1)) )
                return GetOperandValue(addr, 1)
        else:
            break

def get_string(position):
    out = ""
    while True:
        if Byte(position) != 0:
            out += chr(Byte(position))
            #print '%s => %x : %s' % (hex(position) , Byte(position), out)
        else:
            break
        position += 1
    return out

def save_function_addr(addr, func):
    max_addr = addr + 30
    while True:
        addr = idc.NextHead(addr)
        if addr < max_addr:
            if GetMnem(addr) == "mov" and "eax" in GetOpnd(addr, 1):
                MakeName(GetOperandValue(addr,0), "p_"+dec)
                break
        else:
            break

def patch_function_call(addr, func):
    for x in XrefsTo(addr, flags=0):
        sub = GetFunctionAttr(x.frm, FUNCATTR_START)
        MakeName(sub, "call_"+dec)

        
for x in XrefsTo(begin_position_copy, flags=0):
    ref_addr = find_function_arg(x.frm)
    if ref_addr is None:
        continue
    out = get_string(ref_addr)
    dec = decrypt(out)
    print "MakeName => Ref Addr: 0x%x | Decrypted: %s" % (x.frm, dec)
    #sub_addr = idaapi.get_func(x.frm)
    sub = GetFunctionAttr(x.frm, FUNCATTR_START)
    MakeName(sub, "getAddr_"+dec)
    save_function_addr(x.frm, dec)
    patch_function_call(sub, dec)
