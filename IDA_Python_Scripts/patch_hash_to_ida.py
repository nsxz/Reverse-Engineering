#-*-conding:utf-8-*-

''''
读取生成好的function_hash 文件，将函数hash对应的函数名以枚举变量的方式添加到IDA中

注意: 使用当前脚本时，需要根据不同样本修改某些配置，具体如下：
        1. conversion_function ： 样本中通过函数名hash值获取函数地址的函数地址
        2. line:64 
        3. 由于当前脚本使用了中文注释，所以必须保证当前样本编码格式为UTF-8.
'''


import json
import os
debug = True



def get_enum(constant):
  all_enums = GetEnumQty()
  for i in range(0, all_enums):
    enum_id = GetnEnum(i)
    enum_constant = GetFirstConst(enum_id, -1)
    name = GetConstName(GetConstEx(enum_id, enum_constant, 0, -1))
    if int(enum_constant) == constant: return [name, enum_id]
    while True:
      enum_constant = GetNextConst(enum_id, enum_constant, -1)
      name = GetConstName(GetConstEx(enum_id, enum_constant, 0, -1))
      if enum_constant == 0xFFFFFFFF:
        break
      if int(enum_constant) == constant: return [name, enum_id]
  return None


def convert_offset_to_enum(addr):
  constant = GetOperandValue(addr, 0)
  enum_data = get_enum(constant)
  if enum_data:
    name, enum_id = enum_data
    OpEnumEx(addr, 0, enum_id, 0)
    return True
  else:
    return False
  

def enum_for_xrefs(load_function_address, json_data, enumeration):
  for x in XrefsTo(load_function_address, flags=0):
    current_address = x.frm
    if debug:
        print "[+] At address %s => call sub_%s " % (hex(current_address), hex(load_function_address))
    addr_minus_20 = current_address-20 #  according your sample to modify
    push_count = 0
    while current_address >= addr_minus_20:
      current_address = PrevHead(current_address)
      if GetMnem(current_address) == "push":
        push_count += 1
        data = GetOperandValue(current_address, 0)
        if push_count == 2:  									#  The position  of function_hash ,  according your sample to modify
          if data in json_data:
            name = json_data[data]
            AddConstEx(enumeration, str(name), int(data), -1)
            if convert_offset_to_enum(current_address):
              print "[+] Converted 0x%x to %s enumeration" % (current_address, name)
              '''
              # use where sample save function_address to offset_value
              address_plus_30 = current_address+30
              address = current_address
              while address <= address_plus_30:
                address = NextHead(address)
                if GetMnem(address) == "mov":
                  if 'dword' in GetOpnd(address, 0) and 'eax' in GetOpnd(address, 1):
                    operand_value = GetOperandValue(address, 0)
                    MakeName(operand_value, str("d_"+name))
              
              
              address_plus_30 = current_address+30  								# according your sample to modify
              address = current_address
              while address <= address_plus_30:
                address = NextHead(address)
                if GetMnem(address) == "call":
                  if GetOpnd(address, 0)[0] == 'e':
                    operand_value = GetOperandValue(address, 0)
                    print "[operand_value]: %s => [function_name]: %s" % (operand_value, name)
                    break
               '''
              break




fh = open("output.json", 'rb')
d = fh.read()
json_data = json.loads(d)
fh.close()

# JSON objects don't allow using integers as dict keys. Little workaround for
# this issue. 
for k,v in json_data.iteritems():
  json_data[int(k)] = json_data.pop(k)

conversion_function = 0x00401393  # get_function_address_by_hash function address, according your sample to modify
enumeration = GetEnum("hash_functions")
if enumeration == 0xFFFFFFFF:
  enumeration = AddEnum(0, "hash_functions", idaapi.hexflag())
enum_for_xrefs(conversion_function, json_data, enumeration)