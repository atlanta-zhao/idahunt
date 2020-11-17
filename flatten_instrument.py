# -*- coding = utf-8 -*-
from idaapi import *
import idautils 
#import pandas as pd
import struct
import lief
import pefile
import os


ori_op = []         #origin opcode (string)
ori_address = []    #origin address
ori_length = []     #opcode length
                    #call     | # mov         |#jz
args0 = []          #EIP      | #operand1     |no jmp next address
args1 = []          #call dest address  | #operand2     |jmp-to address
args2 = []          #save type : mv  jz  call
ins_index = 0
NEW_SECTION_ADDRESS = 0
(INPUT_PATH,INPUT_PE) = os.path.split(ida_nalt.get_input_file_path())#
#INPUT_PE = 'cmd.exe'#idc.GetInputFilePath() #'test.exe'


POP_DIC = {'eax':'\x58','ecx':'\x59','ebx':'\x5b','edx':'\x5a','esp':'\x5c','ebp':'\x5d','esi':'\x5e','edi':'\x5f'}

#pop eax   58
#pop ebx   5b
#pop ecx   59
#pop edx   5a
#pop esp   5c
#pop ebp   5d
#pop esi   5e
#pop edi   5f

def insert_section(length,data,len_funs):
    global NEW_SECTION_ADDRESS
    bin = lief.parse(INPUT_PE)
    pe = pefile.PE(INPUT_PE)
    section = lief.PE.Section('.test')
    section.virtual_address = (((pe.sections[-1].VirtualAddress + (pe.sections[-1].Misc_VirtualSize)-1)/0x1000+1)*0x1000)
    
    NEW_SECTION_ADDRESS = section.virtual_address
    tmp = open("section_address",'w')
    tmp.write(str(NEW_SECTION_ADDRESS))
    tmp.write('\n')
    tmp.write(str(length-len_funs))
    tmp.write('\n')
    tmp.close()

    section.virtual_size = section.size = length
    section.offset = (((pe.sections[-1].PointerToRawData + (pe.sections[-1].SizeOfRawData)-1)/0x200+1)*0x200)
    section.characteristics = 0x60000020    
    insert_data = []
    for each in data:
        insert_data.append(ord(each))
    section.content = insert_data
    #set random address closed
    bin.optional_header.dll_characteristics =  bin.optional_header.dll_characteristics & 0xffbf  

    bin.add_section(section)
    bin.write("crafted\\"+ INPUT_PE + ".crafted.call")

    
def build_section_data(x,y,flag):
    '''
    push = '\x68' 
    #print args1
    
    tmp = struct.pack("I", args1)
    print args1,'pack:',tmp
    pop = POP_DIC[args0]
    print args0,pop
    retn = '\xc3'
    return push+tmp+pop+retn    
    '''
    if flag == 'call5':
    #print "x",x
    #print "y",y
        ins1 = '\x68' #push
        ret = struct.pack("I", x)
        ins2 = '\xe9' #jmp
        target = struct.pack("I", y)
        return ins1+ret+ins2+target
    if flag == 'call6':
    #print "x",x
    #print "y",y
        ins1 = '\x68'
        ret = struct.pack("I", x)
        ins2 = '\xff\x25' # a type of jmp
        target = struct.pack("I", y)
        return ins1+ret+ins2+target
    if flag == 'mov':
        push = '\x68' 
        #print args1   
        tmp = struct.pack("I", y)
        #print args1,'pack:',tmp
        pop = POP_DIC[x]
        #print args0,pop
        retn = '\xc3'
        return push+tmp+pop+retn    

    if flag == 'jz':
        ins1 = "\x50"     #push eax
        ins2 = "\x51"     #push ecx
        ins3 = "\x9f"     #lahf
        ins4 = "\x50"     #push eax
        ins5 = "\xb1\x0e" #mov cl, 6+8
        ins6 = "\xd3\xe8" #shr eax,cl
        ins7 = "\x83\xe0\x01" #and eax,1
    
        ins8 = "\x69\xc0" + struct.pack("I", (y-x) & 0xffffffff) #struct.pack("I", y-x)imul eax,y-x
        ins9 = "\x05" + struct.pack("I", x & 0xffffffff)
        ins10 = "\x89\x44\x24\x0c"
        ins11 = "\x58"
        ins12 = "\x9e"
        ins13 = "\x59"
        ins14 = "\x58"
        ins15 = "\xc3"
        return ins1+ins2+ins3+ins4+ins5+ins6+ins7+ins8+ins9+ins10+ins11+ins12+ins13+ins14+ins15

    
  
    #return ins1+ins2+ins3+ins4+ins5+ins6+ins7+ins8+ins9+ins10+ins11+ins12+ins13+ins14+ins15
def instrument(origin_op, origin_address):
    if origin_op.startswith('call'):
    	#return
        #if idc.GetOpType(origin_address, 0) == 1 and idc.GetOpType(origin_address, 1) == 5:
        if 1==1:
        	#print hex(origin_address)
            op_length=idaapi.decode_insn(origin_address)
            #print hex(origin_address)
            #return
            if op_length == 6 : 
                #print hex(origin_address)
                #return
                ori_op.append(origin_op)
                ori_address.append(origin_address)
                args0.append(origin_address + 6)
                #print origin_address + 5
                jump_add = (idc.Dword(origin_address+2))
                args1.append(jump_add)
                #print jump_add
                #print "--------"
                print("ori_address:",hex(origin_address),"call6")
                args2.append('call6')

                #args1.append(int(idc.Dword(origin_address+1)))
                #call address
            if op_length == 5 : 
                #print hex(origin_address)
                #return
                ori_op.append(origin_op)
                ori_address.append(origin_address)
                args0.append(origin_address + 5)
                #print origin_address + 5
                jump_add = (idc.Dword(origin_address+1) + 5 + origin_address) & 0xffffffff
                args1.append(jump_add)
                #print jump_add
                #print "--------"
                print("ori_address:",hex(origin_address),"call5")
                args2.append('call5')

                #args1.append(int(idc.Dword(origin_address+1)))
                #call address
    if origin_op.startswith('mov'):
        if idc.GetOpType(origin_address, 0) == 1 and idc.GetOpType(origin_address, 1) == 5:

        	#print hex(origin_address)
            op_length=idaapi.decode_insn(origin_address)
            if op_length != 5: return
            ori_op.append(origin_op)
            ori_address.append(origin_address)
            ori_length.append(op_length)
            args0.append(idc.GetOpnd(origin_address,0))
            args1.append(int(idc.Dword(origin_address+1)))
            args2.append('mov')
            print("ori_address:",hex(origin_address),"mov")
            #call address
    if origin_op.startswith('jz'):
    	#sreturn
        #if idc.GetOpType(origin_address, 0) == 1 and idc.GetOpType(origin_address, 1) == 5:
        if 1==1:
        	#print hex(origin_address)
            op_length=idaapi.decode_insn(origin_address)
            #print hex(origin_address)
            #return
            if op_length != 6: return
            #print hex(origin_address)
            #return
            ori_op.append(origin_op)
            ori_address.append(origin_address)
            args0.append(origin_address + 6)
            #print origin_address + 6
            jump_add = (idc.Dword(origin_address+2) + 6 + origin_address)&0xffffffff
            args1.append(jump_add)
            #print jump_add
            #print "--------"
            args2.append('jz')
            print("ori_address:",hex(origin_address),"jz")


def add_dispatch_function(ori_address, offsets):
    '''
    0418C35 50                   push    eax                       
    0418C36 56                   push    esi
    0418C37 51                   push    ecx
    0418C38 50                   push    eax
    0418C39 9F                   lahf
    0418C3A 50                   push    eax       
    ins1 = "\x50\x56\x51\x50\x9F\x50"   
    0418C3B E8 08 00 00 00       call    loc_418C48
    ins2 = "\xE8" + struct.pack("I", len(ori_address)*8)
    0418C3B                      ; --------------------------------
    0418C40 CE E8 3E D9          dd 0D93EE8CEh  ret_addr
    0418C44 FF FF 8B 7C          dd 7C8BFFFFh   to_addr
    0418C48                      ; --------------------------------
    0418C48
    0418C48                      loc_418C48:                       
    0418C48 5E                   pop     esi
    0418C49 31 C9                xor     ecx, ecx
    0418C4B
    0418C4B                      loc_418C4B:
    0418C4B 8B 04 CE             mov     eax, [esi+ecx*8]
    0418C4E 3B 44 24 14          cmp     eax, [esp+14h]
    0418C52 74 09                jz      short loc_418C5D
    0418C54 41                   inc     ecx
    ins3 = "\x5E\x31\xC9\x8B\x04\xCE\x3B\x44\x24\x14\x74\x09\x41"
    0418C55 81 F9 E8 03 00 00    cmp     ecx, 3E8h      # len(ori_address)
    ins4 = "\x81\xF9" + struct.pack("I", len(ori_address))
    0418C55
    0418C5B 75 EE                jnz     short loc_418C4B
    0418C5D
    0418C5D                      loc_418C5D:
    0418C5D 8B 44 CE 04          mov     eax, [esi+ecx*8+4]  # offset
    ins5 = "\x75\xEE\x8B\x44\xCE\x04"
    0418C61 8D 84 06 01 00 01 00 lea     eax, [esi+eax+10001h]   # add  eax, addr_section
    ins6 = "\x8D\x84\x06" + struct.pack("I", off_section)
    0418C65 89 44 24 10          mov     [esp+10h], eax
    0418C69 58                   pop     eax
    0418C6A 9E                   sahf
    0418C6B 58                   pop     eax
    0418C6C 59                   pop     ecx
    0418C6D 5E                   pop     esi
    0418C6E C3                   retn
    ins7 = "\x89\x44\x24\x10\x58\x9E\x58\x59\x5E\xC3"
    '''
    ins1 = "\x50\x56\x51\x50\x9F\x50"
    ins2 = "\xE8" + struct.pack("I", len(ori_address)*8)
    tab = ""    
    for index in range(len(ori_address)):
        tab += struct.pack("I", ori_address[index]+5)
        tab += struct.pack("I", offsets[index])
    ins3 = "\x5E\x31\xC9\x8B\x04\xCE\x3B\x44\x24\x14\x74\x09\x41"
    ins4 = "\x81\xF9" + struct.pack("I", len(ori_address))
    ins5 = "\x75\xEE\x8B\x44\xCE\x04"

    ins7 = "\x89\x44\x24\x10\x58\x9E\x58\x59\x5E\xC3"
    # off_funs = addr_funs - tab
    off_funs = len(tab) + len(ins3) + len(ins4) + len(ins5) + 7 + len(ins7)
    ins6 = "\x8D\x84\x06" + struct.pack("I", off_funs)
    return ins1+ins2+tab+ins3+ins4+ins5+ins6+ins7


def create_pe():

    text_start = text_end = 0
    for seg in Segments():
        if idc.SegName(seg)==".text":
            text_start=idc.SegStart(seg)
            text_end=idc.SegEnd(seg)
    for func in idautils.Functions():
        start_address = func
        end_address = idc.FindFuncEnd(func)
        #print hex(start_address)
        for each_step in idautils.Heads(start_address, end_address):
            #print hex(each_step)
            op = idc.GetDisasm(each_step)
            if each_step >= text_start and each_step <text_end:
                instrument(op,each_step)

    section_data = ''
    offsets = []
    for index in range(len(ori_op)):
        offsets.append(len(section_data))
        section_data += build_section_data(args0[index],args1[index],args2[index])

    # add dispatch function
    len_funs = len(section_data)
    section_data = add_dispatch_function(ori_address, offsets) + section_data

    section_file = open('newSectionData','wb')
    section_file.write(section_data)
    section_file.close()
    section_size = len(section_data)
    insert_section(len(section_data),section_data,len_funs)

    #ref = pd.DataFrame({'addr':ori_address,"ins":ori_op,'args0':args0,'args1':args1,'length':ori_length})
    #ref.to_csv('ref.txt',index=0)

if __name__ == '__main__':
	#need IDA
    idaapi.autoWait()
    create_pe()
    if "DO_EXIT" in os.environ:
        idc.qexit(1)
