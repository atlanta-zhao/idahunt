from idaapi import *
import idautils 
import pandas as pd
import struct
import lief
import pefile
import random
import os

ori_op = []
ori_address = []
ori_length = []
args0 = []
args1 = []

mv_index = 0
jz_index = 0
call5_index = 0
call6_index = 0
DISPATCH_ADDRESS = 0
FUNCTIONS_ADDRESS = 0


POP_DIC = {'eax':'\x58','ecx':'\x59','ebx':'\x5b','edx':'\x5a','esp':'\x5c','ebp':'\x5d','esi':'\x5e','edi':'\x5f'}

#pop eax   58
#pop ebx   5b
#pop ecx   59
#pop edx   5a
#pop esp   5c
#pop ebp   5d
#pop esi   5e
#pop edi   5f

def instrument_retrieve(origin_op, origin_address):

    global mv_index
    global jz_index
    global call5_index
    global call6_index
    if origin_op.startswith('call'):
        if 1 == 1:
            #return
            
            op_length=idaapi.decode_insn(origin_address)
            if op_length  == 5:             
            #print hex(origin_address)
            #print index
                PatchByte(origin_address, 0xe9) #jmp
                PatchDword(origin_address + 1 ,FUNCTIONS_ADDRESS - origin_address - 5  + 10*call5_index+7*mv_index+31*jz_index+11*call6_index)
                PatchDword(FUNCTIONS_ADDRESS+10*call5_index+7*mv_index+31*jz_index+6 + 11*call6_index, (idc.Dword(FUNCTIONS_ADDRESS+10*call5_index+7*mv_index+31*jz_index+6+ 11*call6_index)-(FUNCTIONS_ADDRESS+10*call5_index+7*mv_index+31*jz_index+10+ 11*call6_index)))
                call5_index += 1
            if op_length  == 6:
                PatchByte(origin_address, 0xe9)
                PatchDword(origin_address + 1 ,FUNCTIONS_ADDRESS - origin_address - 5  + 10*call5_index+7*mv_index+31*jz_index+ 11*call6_index)
                #PatchByte(origin_address + 5 , random.randint(0,255))# random.randint(0,255)
                PatchByte(origin_address + 5 , 0x90)
                call6_index += 1
            #PatchByte(origin_address + 5 , 0x90)
            #print FUNCTIONS_ADDRESS - origin_address -5-5  + 30 * ins_index
            #print FUNCTIONS_ADDRESS
            #print origin_address
    if origin_op.startswith('mov'):
        if idc.GetOpType(origin_address, 0) == 1 and idc.GetOpType(origin_address, 1) == 5:
            op_length=idaapi.decode_insn(origin_address)
            if op_length != 5: return
        
            print hex(origin_address)
            #print index
            PatchByte(origin_address, 0xe8) # call
            PatchDword(origin_address + 1, DISPATCH_ADDRESS - origin_address - 5)
            #PatchDword(origin_address + 1 ,FUNCTIONS_ADDRESS - origin_address - 5  + 10*call5_index+7*mv_index+31*jz_index+ 11*call6_index)
            mv_index += 1
            #print FUNCTIONS_ADDRESS - origin_address - 5  + 10*call_index+7*mv_index+31*jz_index
            #print FUNCTIONS_ADDRESS
            #print origin_address
            #ins_index += 1
            #print hex(origin_address)
    if origin_op.startswith('jz'):
        #return
        if 1 == 1:
            op_length=idaapi.decode_insn(origin_address)
            if op_length != 6: return
            
            print hex(origin_address)
            #print index
            PatchByte(origin_address, 0xe8)
            PatchDword(origin_address + 1, DISPATCH_ADDRESS - origin_address - 5)
            #PatchDword(origin_address + 1 ,FUNCTIONS_ADDRESS - origin_address - 5  + 10*call5_index+7*mv_index+31*jz_index+ 11*call6_index)
            #PatchByte(origin_address + 5 , grandom.randint(0,255))
            PatchByte(origin_address + 5 , 0x90)
            jz_index += 1


def scan_instrument():
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
            #instrument(op,each_step)
            if each_step >= text_start and each_step <text_end:
                instrument_retrieve(op, each_step)
            #print op

def find_changed_bytes():

    changed_bytes = list()

    for seg_start in Segments():
        for ea in range(seg_start, SegEnd(seg_start) ):
            if isLoaded(ea):
                byte = Byte(ea)
                original_byte = GetOriginalByte(ea)
                if byte != original_byte:
                    changed_bytes.append( (ea, byte, original_byte) )
            
    return changed_bytes

def patch_file(data, changed_bytes):
    
    for ea, byte, original_byte in changed_bytes:
        print '%08x: %02x original(%02x)' % (ea, byte, original_byte)
                
        file_offset = idaapi.get_fileregion_offset( ea )
        
        original_char = chr( original_byte )
        char = chr( byte )
        
        if data[ file_offset ] == original_char:
            data[ file_offset ] = char
    
    patched_file = 'new_' + origin_INPUT_PE
    if patched_file:
        with file(patched_file, 'wb') as f:
            f.write( ''.join( data ) )

def generate_new_exe():
    print 'Finding changed bytes...'
    changed_bytes = find_changed_bytes()
    print 'done. %d changed bytes found' % len(changed_bytes)
    
    if changed_bytes:
        original_file = GetInputFilePath()
        print original_file
    
        if not os.path.exists(original_file):
            original_file = idc.AskFile( 0, '*.*', 'Select original file to patch')
        
        if os.path.exists(original_file):

            with file(original_file, 'rb') as f:
                data = list( f.read() )

            patch_file(data, changed_bytes)
        
        else:
            print 'No valid file to patch provided'

    else:
        print 'No changes to patch'
if __name__ == '__main__':
	#need IDA
    #create_pe()
    #need IDA
    #object INPUT_PE + ".crafted" #input_file
    idaapi.autoWait()
    (INPUT_PATH,INPUT_FILE) = os.path.split(ida_nalt.get_input_file_path())#
    #print INPUT_FILE
    origin_INPUT_PE = INPUT_FILE.split('.')[0]+'.'+INPUT_FILE.split('.')[1]
    #origin_INPUT_PE = INPUT_FILE[:-13]
    #print origin_INPUT_PE
    #INPUT_FILE = 'cmd.exe.crafted.call'
    if DISPATCH_ADDRESS == 0:
        tmp = open('..\\' + origin_INPUT_PE + '_section_address','r')
        file_tmp = pefile.PE(INPUT_FILE)
        length = int(tmp.readline())#new section address
        offset = int(tmp.readline())#patch length
        DISPATCH_ADDRESS = length + file_tmp.NT_HEADERS.OPTIONAL_HEADER.ImageBase # 0x400000 base loading address #int
        FUNCTIONS_ADDRESS = DISPATCH_ADDRESS + offset  #int
        print DISPATCH_ADDRESS, FUNCTIONS_ADDRESS
    scan_instrument()

    #file_my1 = open("1.exe","w")
    print '---- Running IDA file patching script  ----'
    generate_new_exe()
    print '---- Script finished ----'

    if "DO_EXIT" in os.environ:
        idc.qexit(1)



