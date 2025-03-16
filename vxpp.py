import pyhidra
import sys
import os

common_vtable_registers:list[str] = ["ax", "cx", "dx", "bx"]

jump_instructions:list[str] = ["jmp", "jne", "je", "jo", "jno", "js", "jns", "jz", "jnz", "jb", "jnae", "jnb", "jc", "jae", "jnc", "jbe", "jna", "ja", "jnbe", "jl", "jnge", "jge", "jnl", "jle", "jg", "jnle", "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz"]

x64_argument_regs = ["rcx", "rdx", "r8", "r9"]

def get_cfg_functions(listing, iterator, bin)->[list, str]:
    cfg_list = []
    cfg_reference_list = ""
    while iterator.hasNext():
        func = iterator.next()
        if "guard_" in str(func.getName()).lower():
            cfg_list.append(func.getEntryPoint())
            cfg_reference_list += str(bin.getReferencesTo(func.getEntryPoint()))
    return [cfg_list, cfg_reference_list]

cfg_list = []

def get_call_count(instructions_readable:list[str]):
    call_count:int = 0
    for instr in instructions_readable:
        if "CALL" in instr.upper():
            call_count+=1
    return call_count

"""
#Look for a virtual function calling other virtual functions in a loop, get its location in the vtable and get the vtable address
#Pass a disassembled ghidra function in the argument
#Check to make sure the jump is not offset from any instruction, so it will keep on executing the same stuff 
#Check to make sure the loop iterates
"""
def verify_jump_to_instruction(instructions, jump_target:int) -> bool:
    for ind, instr in enumerate(instructions):
        if jump_target==int(str(instr.getAddress()), 16):
            return True
    return False


def get_disassembly(program, func) -> None:
    if func is None:
        return "None"
    print(type(func))
    func.getDisassembler()
    breakpoint()
    disassembler = program.getListing().getDisassembler(func.getBody())
    print(disassembler.getInstructions(func.getBody()))

def convert_to_str_list(instructions:list) -> list[str]:
    returnable:list[str] = []
    for i in instructions:
        returnable.append(str(i))
    return returnable

def contains_instruction(instructions:list[str], inst:str) -> bool:
    for i in instructions:
        if inst.lower() in i.lower():
            return True
    return False
    
def instruction_index(instructions:list[str], inst:str) -> int:
    for ind, i in enumerate(instructions): #Index, instruction for enumerate, just remember
        if inst.lower() in i.lower():
            return ind
    return -1

def instruction_ind_reg(instructions:list[str], inst:str) -> int:
    for ind, i in enumerate(instructions): #Index, instruction for enumerate, just remember
        if inst.lower() in i.lower() and "0x" not in inst:
            return ind
    return -1
    

def instruction_ind_not_reg(instructions:list[str], inst:str) -> int:
    for ind, i in enumerate(instructions): #Index, instruction for enumerate, just remember
        if inst.lower() in i.lower() and "0x" in inst:
            return ind
    return -1

"""
ARITH-G Conditions:
    #1. Call 
    #2. Jmp target before call address,
    #3. Check for use of conventional registers and instructions for vtable calls
    #4. __guard_dispatch_icall_fptr call (If true, add usability level by 1)
    #Disqualifiers: No ret, function too long
"""
def is_arithg(instructions:list, addr_set, bin): 
    instructions_readable = convert_to_str_list(instructions)
    allowed_instrs:list[str] = ["mov", "lea", "add", "sub", "nop"]
    working_instr = False
    if len(instructions_readable)<4: #Prevent out of bounds errors
        return False
    for ind, instr in enumerate(instructions_readable[:-1]):
        if 'sp' in instr.lower() or 'bp' in instr.lower():
            continue
        if "call" in instr.lower() or 'j' in instr.lower() or "loop" in instr.lower():
            return False
        for valid in allowed_instrs:
            if valid.lower() not in instr.lower():
                return False
            if valid.lower() in instr:
                working_instr = True
    return working_instr

"""
r64 loader gadget:
    #1: Mov instruction to a 64-bit instruction, loads a dereferenced address
Disqualifiers: No ret, too long
"""
def is_r64_g(instructions:list, addr_set):
    instructions_readable = convert_to_str_list(instructions)
    
    if len(instructions_readable)==0:
        return [False, ""]
        
    if "ret" not in instructions_readable[-1].lower():
        return [False, ""]
        
    register_count = [0, 0, 0]
    for reg_ind, reg in enumerate(x64_argument_regs):
        for instr in instructions_readable:
            if reg in instr:
                register_count[reg_ind]+=1
                
    important_reg_count = sum(1 for x in register_count if x>0)
    if important_reg_count!=1:
        return [False, ""]
        
    ireg = 0
    for i, count in register_count:
        if i!=0:
            ireg = i
            
    creg = x64_argument_regs[ireg]
    for instruction in instructions_readable:
        if "mov" in instruction.split(' ')[0].lower() and creg in instruction.split(' ')[1] and '[' in instruction:
            return [True, creg]
            
    return [False, ""]

def check_xfg(instructions:list[str], call_ind:int)->str:
    if call_ind>len(instructions) or call_ind-4<0:
        return "NULL"
    for ind, instr in enumerate(instructions[call_ind-4:call_ind], start=call_ind-4):
        if len(instr.split(' '))!=2 or len(instr.split(','))!=2:
            continue
        if "mov" in instr.lower() and "r10" in instr.lower() and len(instr.split(',')[1])>10:
            return instr.split(',')[1][1:]
    return "NULL"

"""
ML-G Criteria:
    #1: Is there a VTABLE call?
    #2: Is the jump after the call and does it go before the call, is it within the function?
    #3: Is the call protected by CFG?
    
#Check for loop gadgets in general, check if it is coming from a dispatch table or VTable
"""
def is_mlg(instructions:list, addr_set, bin) -> [bool, int]:
    #Find the VTABLE where the start of the function base is mentioned
    instructions_readable = convert_to_str_list(instructions)
    if len(instructions_readable)==0:
        return [False, 0, "NULL"]
    if "ret" not in instructions_readable[-1].lower():
        return [False, 0, "NULL"]
    if instruction_ind_reg(instructions_readable, 'CALL')==-1: #Make it contain a register
        return [False, 0, "NULL"]        


    conditionals:list[bool] = [False, False, False]
    usability:int = 0

    modified_regs:list = []
    call_regs:list = []
    vtable_indexes = []
    call_indexes = []
    #For the modified_reg, the first instance needs to be just in [] of length 3 
    for ind, instr in enumerate(instructions_readable):
        
        if 'sp' in instr.lower() or 'bp' in instr.lower():
            continue
        
        if len(instr.split(','))<=1:
            continue
        
        right_instr = instr.split(',')[1] 
        start_ind = right_instr.find("[")
        end_ind = right_instr.find("]")
        
        if start_ind>-1 and end_ind>-1:
            deref_markers = 0
            drefin_instr:str = instr[start_ind:end_ind+1]
            
            if len(drefin_instr)==5 and len(drefin_instr.strip('[').strip(']')):
                deref_markers+=1
                
            dref_sp:list[str] = drefin_instr.split(" ")
            for dind, deref in enumerate(dref_sp):
                if len(deref.strip('[').strip(']'))==3 and deref[0]=='[' and deref[-1]==']' '0x' not in deref:
                    pass
            if deref_markers==1:
                first_seg = instr.split(",")[0].lower() 
                to_set = first_seg.split(' ')[1]
                if 'word' in to_set:
                    print(f"WORD almost added to register in {instr}")
                    continue
                modified_regs.append(to_set)#Isue
                vtable_indexes.append(ind)

    deref_inds = []
    for i in vtable_indexes:
        #It should be in the next 6 instructions
        #It should be a mov new_reg, [deref'd reg]
        for ind, instr in enumerate(instructions_readable[i:i+6], start=i):
            if instr.split(' ')[0].lower()!="mov":
                continue
            if ind>i+6:
                break
            if '[' in instr and ']' in instr:
                start_ind = instr.find("[")
                end_ind = instr.find("]")

                deref_substr = instr[start_ind+1:end_ind] #Problem 2
                deref_ind = ind

                for modified_reg in modified_regs:
                    if 'sp' in modified_reg.lower() or 'bp' in modified_reg.lower():
                        continue
                    #check the first split to see if it is a modified reegister
                    if len(deref_substr.split(' '))==3:
                        if modified_reg in deref_substr.split(' ')[0].lower() and '+' in deref_substr.split(' ')[1].lower() and deref_substr.split(' ')[2].lower()[0:2]=='0x' and int(deref_substr.split(' ')[2].lower(), 16)%4==0:
                            call_regs.append(instr.split(" ")[1].split(",")[0])
                            call_indexes.append(ind)
                            deref_inds.append(deref_ind)
                    elif modified_reg.lower() in deref_substr.lower():
                        call_regs.append(instr.split(",")[0].split(" ")[-1]) #Appends qword
                        call_indexes.append(ind)
                        deref_inds.append(deref_ind)    
    call_addr = 0
    
    #Is there a virtual method called?
    #Check to make sure that the call is after the vtable function
    call_hash="NULL"
    for i in call_indexes: #what about guard check?
        for ind, instr in enumerate(instructions_readable[i:], start=i):
            #Check any xrefs of the function from a vtable
            if len(instr.split(" ")) >0 and instr.split(" ")[0].lower()=="call":
                for reg in call_regs: #Also check modified_regs
                    #Add an alternative to check if the function is being passed as a parameter and if there is a control flow guard check
                    #Check if the dereference contains guard
                    if reg in instr[instr.find(' '):] or "guard" in instr: #Sometimes the register is directly called and modified without updating the dereference
                        #Calls something dereferenced by a pointer
                        conditionals[0] = True
                        call_addr = int(str(instructions[ind].getAddress()), 16)
                        call_hash = check_xfg(instructions_readable, ind)
                        break
                    else:
                        if len(instr.split(' '))==4:
                            #Could be a variant of mov
                            cfg_reference_list = get_cfg_functions(bin.getCurrentProgram().getListing(), bin.getCurrentProgram().getFunctionManager().getFunctions(True), bin)[1]
                            if instr.split(' ')[3][0:3]=="[0x" and instr[instr.find('[')+3:instr.find(']')] in cfg_reference_list:#Remove the last and if needed
                                address = int(instr[instr.find('[')+1:instr.find(']')], 16)
                                conditionals[0] = True
                                call_addr = int(str(instructions[ind].getAddress()), 16)
                                call_hash = check_xfg(instructions_readable, ind)
                                break
                                
                if not conditionals[0] and '[' in instr and ']' in instr:
                    for reg in modified_regs:
                        start_sub = instr.find('[')
                        end_sub = instr.find(']')
                        deref_substr = instr[start_sub+1:end_sub]
                        if reg in deref_substr:
                            conditionals[0] = True
                            call_addr = int(str(instructions[ind].getAddress()), 16)
    jump_to = 0
    jump_address = 0

    #Is the jump within the function?
    for ind, i in enumerate(instructions_readable):
        for j in jump_instructions:
            if i.split(" ")[0].lower()==j:
                if len(i.split(' '))==2 and i.split(' ')[1][0:2]=='0x':
                    if (jump_target:=int(i.split(" ")[1], 16))>=int("0x"+str(addr_set).split(',')[0][2:], 16) and jump_target<=int("0x"+str(addr_set).split(' ')[1].strip(']'), 16):
                        conditionals[1] = True
                        jump_address = int(str(instructions[ind].getAddress()), 16)
                        jump_to = jump_target


    if conditionals[0] and conditionals[1] and jump_to!=0 and call_addr!=0 and call_addr>=jump_to and call_addr<jump_address and verify_jump_to_instruction(instructions, jump_to):
        conditionals[2] = True
        
    return [True if conditionals[0] and conditionals[1] and conditionals[2] else False, 0, call_hash] #usability not added yet

"""
INV-G (Strict) Criteria:
    #1: Is there a VTABLE call?
    #2: Is the jump after the call and does it go before the call, is it within the function?
    #3: Is the call protected by CFG?
Disqualifiers: No ret, too long
"""
def is_inv_g_strict(instructions:list, addr_set, bin):

    instructions_readable = convert_to_str_list(instructions)
    if len(instructions_readable)==0:
        return [False, 0, "NULL"]
    if "ret" not in instructions_readable[-1].lower():
        return [False, 0, "NULL"]
    if instruction_ind_reg(instructions_readable, 'CALL')==-1: #Make it contain a register
        return [False, 0, "NULL"]        

    conditionals:list[bool] = [False, False, False]
    usability:int = 0

    modified_regs:list = []
    call_regs:list = []
    vtable_indexes = []
    call_indexes = []
    #For the modified_reg, the first instance needs to be just in [] of length 3 
    for ind, instr in enumerate(instructions_readable):
        if 'sp' in instr.lower() or 'bp' in instr.lower():
            continue
        if len(instr.split(','))<=1:
            continue
        right_instr = instr.split(',')[1] 
        start_ind = right_instr.find("[")
        end_ind = right_instr.find("]")
        if start_ind>-1 and end_ind>-1:
            deref_markers = 0
            drefin_instr:str = instr[start_ind:end_ind+1]
            if len(drefin_instr)==5 and len(drefin_instr.strip('[').strip(']')):
                deref_markers+=1
            dref_sp:list[str] = drefin_instr.split(" ")
            for dind, deref in enumerate(dref_sp):
                if len(deref.strip('[').strip(']'))==3 and deref[0]=='[' and deref[-1]==']' '0x' not in deref: #esp+0x3
                    pass
            if deref_markers==1:
                #If length of split==2, then get anything within []
                #Get the first word after [ within [] on the last of split
                first_seg = instr.split(",")[0].lower() 
                to_set = first_seg.split(' ')[1]
                if 'word' in to_set:
                    print(f"WORD almost added to register in {instr}")
                    continue
                modified_regs.append(to_set)#Isue
                vtable_indexes.append(ind)

    deref_inds = []
    for i in vtable_indexes:
        #It should be in the next 6 instructions
        #It should be a mov new_reg, [deref'd reg]
        for ind, instr in enumerate(instructions_readable[i:i+6], start=i):
            if instr.split(' ')[0].lower()!="mov":
                continue
                
            if ind>i+6:
                break
                
            if '[' in instr and ']' in instr:
                start_ind = instr.find("[")
                end_ind = instr.find("]")

                deref_substr = instr[start_ind+1:end_ind] #Problem 2
                deref_ind = ind
                
                for modified_reg in modified_regs:
                    if 'sp' in modified_reg.lower() or 'bp' in modified_reg.lower():
                        continue
                        
                    #check the first split to see if it is a modified reegister
                    if len(deref_substr.split(' '))==3:
                        if modified_reg in deref_substr.split(' ')[0].lower() and '+' in deref_substr.split(' ')[1].lower() and deref_substr.split(' ')[2].lower()[0:2]=='0x' and int(deref_substr.split(' ')[2].lower(), 16)%4==0:
                            call_regs.append(instr.split(" ")[1].split(",")[0])
                            call_indexes.append(ind)
                            deref_inds.append(deref_ind)
                            
                    elif modified_reg.lower() in deref_substr.lower():
                        call_regs.append(instr.split(",")[0].split(" ")[-1]) #Appends qword
                        call_indexes.append(ind)
                        deref_inds.append(deref_ind)
    call_addr = 0
    
    #Is there a virtual method called?
    #Check to make sure that the call is after the vtable function
    call_hash="NULL"
    for i in call_indexes: #what about guard check?
        for ind, instr in enumerate(instructions_readable[i:], start=i):
            #Check any xrefs of the function from a vtable
            if len(instr.split(" ")) >0 and instr.split(" ")[0].lower()=="call":
                for reg in call_regs: #Also check modified_regs
                    #Add an alternative to check if the function is being passed as a parameter and if there is a control flow guard check
                    #Check if the dereference contains guard
                    if reg in instr[instr.find(' '):] or "guard" in instr: #Sometimes the register is directly called and modified without updating the dereference
                        #Calls something dereferenced by a pointer
                        conditionals[0] = True
                        call_addr = int(str(instructions[ind].getAddress()), 16)
                        call_hash = check_xfg(instructions_readable, ind)
                        break
                    else:
                        if len(instr.split(' '))==4:
                            #Could be a variant of mov

                            cfg_reference_list = get_cfg_functions(bin.getCurrentProgram().getListing(), bin.getCurrentProgram().getFunctionManager().getFunctions(True), bin)[1]
                            
                            if instr.split(' ')[3][0:3]=="[0x" and instr[instr.find('[')+3:instr.find(']')] in cfg_reference_list:#Remove the last and if needed
                                address = int(instr[instr.find('[')+1:instr.find(']')], 16)
                                conditionals[0] = True
                                call_addr = int(str(instructions[ind].getAddress()), 16)
                                call_hash = check_xfg(instructions_readable, ind)
                                break
                if not conditionals[0] and '[' in instr and ']' in instr:
                    for reg in modified_regs:
                        start_sub = instr.find('[')
                        end_sub = instr.find(']')
                        deref_substr = instr[start_sub+1:end_sub]
                        
                        if reg in deref_substr:
                            conditionals[0] = True
                            call_addr = int(str(instructions[ind].getAddress()), 16)
    return [True if conditionals[0] else False, 0, call_hash] #usability not added yet
    
"""
INV-G (Strict) Criteria:
    #1: Is there a VTABLE call?
    #2: Is the jump after the call and does it go before the call, is it within the function?
    #3: Is the call protected by CFG?
Disqualifiers: No ret, too long
"""
def is_inv_g_general(instructions:list, addr_set, bin):
    instructions_readable = convert_to_str_list(instructions)
    conditionals= [False]
    if len(instructions_readable)==0:
        return [False, 0, "NULL"]
    if "ret" not in instructions_readable[-1].lower():
        return [False, 0, "NULL"]
    if instruction_ind_reg(instructions_readable, 'CALL')==-1: #Make it contain a register
        return [False, 0, "NULL"]        
    call_hash="NULL"
    for ind, instr in enumerate(instructions_readable):
        #Check any xrefs of the function from a vtable
        if len(instr.split(" ")) >0 and instr.split(" ")[0].lower()=="call":
            if 'x' in instr[instr.find(' '):] or 'r' in instr[instr.find(' '):] or "guard" in instr: #Sometimes the register is directly called and modified without updating the dereference
                #Calls something dereferenced by a pointer
                conditionals[0] = True
                call_hash = check_xfg(instructions_readable, ind)
                break
            else:
                if len(instr.split(' '))==4:
                    #Could be a variant of mov
                    cfg_reference_list = get_cfg_functions(bin.getCurrentProgram().getListing(), bin.getCurrentProgram().getFunctionManager().getFunctions(True), bin)[1]
                    if instr.split(' ')[3][0:3]=="[0x" and instr[instr.find('[')+3:instr.find(']')] in cfg_reference_list:#Remove the last and if needed
                        address = int(instr[instr.find('[')+1:instr.find(']')], 16)
                        conditionals[0] = True
                        call_hash = check_xfg(instructions_readable, ind)
                        break
    return [True if conditionals[0] else False, 0, call_hash] #usability not added yet

"""
Type of invoker gadget based on system argument
"""
def is_inv_g(instructions, addr_set, bin):
    returnable = is_inv_g_strict(instructions, addr_set, bin)
    returnable.append(True)
    if not returnable[0]:
        returnable = is_inv_g_general(instructions, addr_set, bin)
        returnable.append(False)
    return returnable

def test_ghidra():
    if len(sys.argv)<2:
        print("Invalid arguments\nTry: python {} binary_name_here.exe".format(__file__.split("/")[-1]))
        print("\nSyntax: python3 file.py binary max_gadget_len arguments")
        print("\nPossible Arguments:\n\t-t - Include thunk functions\n\t-i - Less strict invoker vfgadgets")
        print("\nExample(s): \npython3 vxpp.py binary max_gadget_len -ti\npython3 vxpp.py binary max_gadget_len")
        exit()
    try:
        with open(f"{sys.argv[1]}", 'r') as file:
            pass
    except FileNotFoundError:
        print(f"File: {sys.argv[1]} not found")
        exit()
    try:
        with pyhidra.open_program(f"{sys.argv[1]}") as bin:
            pass
    except ValueError:
        print("[!] Ghidra Installation Not Found")
        print("\nPlease set your GHIDRA_INSTALL_DIR environment variable to your ghidra installation directory\nHint: If you are on Linux, run \'which ghidra\' to find the installation directrory")
        exit()

"""
VFuncs:
#Get the address of the VTABLE functions, then get the address of the call instruction,
#Get the function start address
#Check JMPs and dereferences
#Add a normal register and a multiply arch term that need to be found
#Check if register's move instruction has [r1 + arch*r2], if so, check if that register is dereferenced before a call instruction, check if the register that is dereferencing it is being called
#So Search for get inside the [] and see if it has 1 register + another register*arch, don't check what it is, only check what it is being moved to, then check if that is being dereferenced just with [], track all dereferences of it to see if the deref is called
#If there is a jump instruction, if it is > than the function base and < than the call, continue
"""
def get_vfuncs(program):
    manager = program.getFunctionManager()
    s_table = program.getSymbolTable()
    virtual_functions = []
    virtual_tables = []
    virtual_offsets = []
    for s in s_table.getAllSymbols(True):
        if "vtable" in s.getName().lower() or "vftable" in s.getName().lower():
            addie = s.getAddress()
            vtable_address = s.getAddress()
            pointer_size:int = addie.getPointerSize()
            addie.addWrap(pointer_size)
            nav_vtables = True
            offset = 0x0
            while nav_vtables:
                if offset>=0x40:
                    nav_vtables = False
                    break
                v_data = program.getListing().getDataAt(addie)
                if v_data is None:
                    nav_vtables = False
                    break
                vtable_data = program.getListing().getDataAt(addie).getValue()
                if vtable_data==None:
                    nav_vtables = False
                    break
                virtual_functions.append(vtable_data)
                virtual_tables.append(vtable_address)
                virtual_offsets.append(hex(offset))
                offset+=pointer_size
                addie = addie.addWrap(pointer_size)
    return [virtual_functions, virtual_tables, virtual_offsets]

def is_virtual(virtual_functions, func):
    for vf_ind, vfunc in enumerate(virtual_functions):
        if str(func.getEntryPoint()).lower() in str(vfunc).lower():
            return True, vf_ind
    return False, -1

def set_max_length() -> int:
    max_len:int = 30
    try:
        max_len=int(sys.argv[2])
    except ValueError:
        print("No instruction limit set, setting it to 30")
        print("The instruction limit is the 2nd argument when running this script\nExample python3 vxpp.py 20")
    return max_len

def main() -> None:
    print("Virtual eXploiter++ v0.1.1\n")
    test_ghidra()
    print("[+] Opening Ghidra...")
    max_len:int = set_max_length()
    pyhidra.start()
    print("\n[+] Analyzing Binary...\n")
    with pyhidra.open_program(f"{sys.argv[1]}") as bin: 
        program = bin.getCurrentProgram()
        vfuncs_list = get_vfuncs(program)
        manager = program.getFunctionManager()
        iterator = manager.getFunctions(True)
        virtual_functions = vfuncs_list[0]
        virtual_tables = vfuncs_list[1]
        virtual_offsets = vfuncs_list[2]

        func_list = []
        print("\n[+] Finding vfgadgets...\n")
        gadgets_found = False
        try:
            args = sys.argv[3]
        except IndexError:
            args = ""
        while iterator.hasNext(): #Instead of finding all the functions, get all of the objects, then get the functions in the vtables and go through it that way, then revert back to this if that fails.
            func = iterator.next()
            if func.isThunk() and not "t" in args:
                continue
            instructions:list[str] = list(program.getListing().getInstructions(func.getBody(), 1))
            if len(instructions)>max_len:
                continue
            is_vfunc, vf_ind = is_virtual(virtual_functions, func)
            mlg_data = is_mlg(instructions, func.getBody(), bin)
            is_loop, xfg_hash = mlg_data[0], mlg_data[2]
            if is_loop and is_vfunc:
                print(f"Main Loop Gadget found at function address: {func.getEntryPoint()}, with the name: {func.getName()} in vtable: {virtual_tables[vf_ind]} at vtable offset: {virtual_offsets[vf_ind]}")
                gadgets_found = True 
                if xfg_hash.lower()!="null":
                    print(f"\t- XFG Hash: {xfg_hash}")
                continue
            if is_loop and not is_vfunc:
                print(f"Potential Main Loop Gadget found at: {func.getEntryPoint()}, with the function name: {func.getName()}")
                gadgets_found = True
                if xfg_hash.lower()!="null":
                    print(f"\t- Gadget likely calls a function with XFG Hash: {xfg_hash}")
                continue
            is_arith = is_arithg(instructions, func.getBody(), bin)
            if is_arith:
                print(f"Potential Arithmetic gadget found at: {func.getEntryPoint()}")
                gadgets_found = True
            loader_specs = is_r64_g(instructions, func.getBody())
            is_r64_loader = loader_specs[0]
            loaded_reg = loader_specs[1]
            if is_r64_loader:
                print(f"Potential register loader gadget for {loaded_reg} found at: {func.getEntryPoint()}")
                gadgets_found = True
            invoker_data = is_inv_g(instructions, func.getBody(), bin)
            is_invoker = invoker_data[0]
            xfg_hash = invoker_data[2]
            is_vtable = invoker_data[3]
            if is_invoker:
                if not 'i' in args and not is_vtable:
                    continue
                if is_vfunc:
                    print(f"Invoker Gadget found at function address: {func.getEntryPoint()}, with the name: {func.getName()} in vtable: {virtual_tables[vf_ind]} at vtable offset: {virtual_offsets[vf_ind]}")
                else:
                    print(f"Potential Invoker Gadget found at: {func.getEntryPoint()}, with the function name: {func.getName()}")
                gadgets_found = True
                if xfg_hash.lower()!="null":
                    print(f"\t- Gadget likely calls a function with XFG Hash: {xfg_hash}")
                continue
    if not gadgets_found:
        print("No suitable VFGadgets were found")

if __name__=="__main__":
    main()
