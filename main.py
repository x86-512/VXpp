import pyhidra
import sys
import os
import jpype

#Remember to add XFG option
#To bypass xfg, find a virtual function with the same hash

############NOTES ON XFG#################
#Get the old virtual function's parameters and return type and search other functions for those same specs
#functiondb.getReturnType()
#functiondb.getParameters()


#Doesn't work
os.system("export GHIDRA_INSTALL_DIR=/usr/share/ghidra")
#GHIDRA_INSTALL_DIR = os.getenv("GHIDRA_INSTALL_DIR")

common_vtable_registers:list[str] = ["ax", "cx", "dx", "bx"]

jump_instructions:list[str] = ["jmp", "jne", "je", "jo", "jno", "js", "jns", "jz", "jnz", "jb", "jnae", "jnb", "jc", "jae", "jnc", "jbe", "jna", "ja", "jnbe", "jl", "jnge", "jge", "jnl", "jle", "jg", "jnle", "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz"]


def dereference_pointer(listing, genericAddress):
    pointer_size = genericAddress.getPointerSize()
    print(pointer_size)
    print(listing.getDataAt(genericAddress))
    breakpoint()
    address = ""
    address += ""
    for i in range(pointer_size-1):
        address+=0


def get_cfg_functions(listing, iterator, bin)->[list, str]:
    cfg_list = []
    cfg_reference_list = ""
    while iterator.hasNext():
        func = iterator.next()
        if "guard_" in str(func.getName()).lower():
            cfg_list.append(func.getEntryPoint())
            #print(type(func.getEntryPoint()))
            #print(func.getEntryPoint())
            #print(bin.getReferencesTo(func.getEntryPoint()))
            cfg_reference_list += str(bin.getReferencesTo(func.getEntryPoint()))
            #print(listing.getDefinedDataAt(func.getEntryPoint()))
            #dereference_pointer(listing, func.getEntryPoint())
            #breakpoint()
    #print(cfg_reference_list)
    return [cfg_list, cfg_reference_list]

cfg_list = []

def get_call_count(instructions_readable:list[str]):
    call_count:int = 0
    for instr in instructions_readable:
        if "CALL" in instr.upper():
            call_count+=1
    return call_count

#Look for a virtual function calling other virtual functions in a loop, get its location in the vtable and get the vtable address
#Pass a disassembled ghidra function in the argument

#Check to make sure the jump is not offset from any instruction, so it will keep on executing the same stuff 
def verify_jump_to_instruction(instructions, jump_target:int) -> bool:
    for ind, instr in enumerate(instructions):
        if jump_target==int(str(instr.getAddress()), 16):
            return True
    return False

#Check to make sure the loop iterates

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
    #4 Conditions:
    #1. Call 
    #2. Jmp target before call address,
    #3. Check for use of conventional registers and instructions for vtable calls
    #4. __guard_dispatch_icall_fptr call (If true, add usability level by 1)
    #5. (Planned) Check if the gadget matches the parameter and return type of another function for XFG
    #Disqualifiers: No ret, function too long, 
    #If CFG is not met, the confidence level goes down


#BUG: the MLG must be the first entry of the vtable
def is_mlg(instructions:list, addr_set, bin) -> [bool, int]:
    #Find the VTABLE where the start of the function base is mentioned

    instructions_readable = convert_to_str_list(instructions)
    if len(instructions_readable)==0:
        return [False, 0]
    if "ret" not in instructions_readable[-1].lower():
        return [False, 0]
    if instruction_ind_reg(instructions_readable, 'CALL')==-1: #Make it contain a register
        return [False, 0]        
    if get_call_count(instructions_readable)!=1:
        return [False, 0]
    #1: Is there a VTABLE call?
    #2: Is the jump after the call and does it go before the call, is it within the function?
    #3 (Bonus): Is the call protected by CFG?
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
            #print(drefin_instr)
            dref_sp:list[str] = drefin_instr.split(" ")
            for dind, deref in enumerate(dref_sp):
                if len(deref.strip('[').strip(']'))==3 and deref[0]=='[' and deref[-1]==']' '0x' not in deref: #esp+0x3
                    #print(deref.strip('[').strip(']'))
                    #print('TRUE 1')
                    pass
                    #deref_markers +=1
                #elif '*' in deref:
                    #print("TRUE 2")
                    #deref_markers += 1
            if deref_markers==1:
                #If length of split==2, then get anything within []
                #Get the first word after [ within [] on the last of split
                #modified_regs.append(instr.split(" ")[1].split(",")[0].lower())#Isue
                first_seg = instr.split(",")[0].lower() 
                to_set = first_seg.split(' ')[1]
                if 'word' in to_set:
                    print(f"WORD almost added to register in {instr}")
                    continue
                #print(to_set)
                #if '[' in first_seg:
                #    within_brackets = first_seg[first_seg.find('['):]
                #    within_no_brackets = within_brackets.strip('[').strip(']')
                    #to_set = within_no_brackets.split(' ')[0]
                modified_regs.append(to_set)#Isue
                #print(f"Modified {modified_regs}")
                vtable_indexes.append(ind)

    for i in vtable_indexes:
        #It should be in the next 6 instructions
        #It should be a mov new_reg, [deref'd reg]
        for ind, instr in enumerate(instructions_readable[i:i+6], start=i):
            #print(instr.split(' ')[0])
            if instr.split(' ')[0].lower()!="mov":
                continue
            #    print("Continuing: {instr}")
            if ind>i+6:
                break
            if '[' in instr and ']' in instr:
                start_ind = instr.find("[")
                end_ind = instr.find("]")

                deref_substr = instr[start_ind+1:end_ind] #Problem 2
                #print(deref_substr)
                #print(deref_substr)
                #print(modified_regs)

                #breakpoint()
                for modified_reg in modified_regs:
                    #print(modified_reg)
                    if 'sp' in modified_reg.lower() or 'bp' in modified_reg.lower():
                        continue
                    #print(f"Current Reg: {modified_reg}")
                    #print(f"deref_substr: {deref_substr}")
                    #check the first split to see if it is a modified reegister
                    if len(deref_substr.split(' '))==3:
                        if modified_reg in deref_substr.split(' ')[0].lower() and '+' in deref_substr.split(' ')[1].lower() and deref_substr.split(' ')[2].lower()[0:2]=='0x' and int(deref_substr.split(' ')[2].lower(), 16)%4==0:
                            call_regs.append(instr.split(" ")[1].split(",")[0])
                            call_indexes.append(ind)
                            #print(call_regs)
                            #breakpoint()
                    elif modified_reg.lower() in deref_substr.lower():
                        #print("\n\n\nIT'S FINALLY TRUE :D\n\n\n")
                        #if len(instr[start_ind+1:end_ind])==3 and instr[start_ind+1:end_ind].lower()==modified_reg:
                        call_regs.append(instr.split(",")[0].split(" ")[-1]) #Appends qword
                        call_indexes.append(ind)
                        #print(instr)
    
    call_addr = 0

    #print(f"Call: {call_indexes}")

    #if len(call_indexes)>0:
    #    print("Call index")
    #if len(call_regs)>0:
    #    print("Call regs")
    #print(f"Vtable Reference: {vtable_indexes}")

    #print(instructions_readable)

    #Is there a virtual method called?
    #Check to make sure that the call is after the vtable function
    for i in call_indexes: #what about guard check?
        for ind, instr in enumerate(instructions_readable[i:], start=i):
            #Check any xrefs of the function from a vtable
            if len(instr.split(" ")) >0 and instr.split(" ")[0].lower()=="call":
                for reg in call_regs: #Also check modified_regs
                    #Add an alternative to check if the function is being passed as a parameter and if there is a control flow guard check
                    #Check if the dereference contains guard
                    if reg in instr[instr.find(' '):] or "guard" in instr: #Sometimes the register is directly called and modified without updating the dereference
                        #Calls something dereferenced by a pointer
                        #print("\n\nTRUE\n\n")

                        #print(instructions[ind].getAddress())
                        #print(reg)
                        conditionals[0] = True
                        call_addr = int(str(instructions[ind].getAddress()), 16)
                        #print(int(str(instructions[ind].getAddress()), 16))
                        #print(f"Call before: {instructions[ind].getAddress()}")
                        break
                    else:
                        if len(instr.split(' '))==4:
                            #Could be a variant of mov

                            cfg_reference_list = get_cfg_functions(bin.getCurrentProgram().getListing(), bin.getCurrentProgram().getFunctionManager().getFunctions(True), bin)[1]
                            if instr.split(' ')[3][0:3]=="[0x" and instr[instr.find('[')+3:instr.find(']')] in cfg_reference_list:#and "AX" in instructions_readable[ind-1].split(',')[0] and "MOV" in instructions_readable[ind-1].split(' ')[0]: #Figure out how to get it to check for CFG
                                #print("\n\nTRUE2\n\n")
                                address = int(instr[instr.find('[')+1:instr.find(']')], 16)
                                #print(instr[instr.find('[')+1:instr.find(']')])
                                conditionals[0] = True
                                call_addr = int(str(instructions[ind].getAddress()), 16)
                                #print(int(str(instructions[ind].getAddress()), 16))
                                #print(f"Call before: {instructions[ind].getAddress()}")
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
                #print("X")
                #print(i)
                #Try doing index of 0x up until you reach a space or ] or the end
                #if len(i.split(' '))==2:
                    #print(i.split(' ')[1][0:2]=='0x')
                if len(i.split(' '))==2 and i.split(' ')[1][0:2]=='0x':
                    #print("Y")
                    # and '*' not in instr and '/' not in instr and '-' not in instr and '+' not in instr:
                    #print(int(i.split(" ")[1], 16))
                    #print(int("0x"+str(addr_set).split(',')[0][2:], 16))
                    #print(int(i.split(" ")[1], 16)>=int("0x"+str(addr_set).split(',')[0][2:], 16))
                    #print(int("0x"+str(addr_set).split(' ')[1].strip(']'), 16))
                    if (jump_target:=int(i.split(" ")[1], 16))>=int("0x"+str(addr_set).split(',')[0][2:], 16) and jump_target<=int("0x"+str(addr_set).split(' ')[1].strip(']'), 16):
                        #print("\n\nTRUE 2\n\n")
                        conditionals[1] = True
                        jump_address = int(str(instructions[ind].getAddress()), 16)
                        jump_to = jump_target


    if conditionals[0] and conditionals[1] and jump_to!=0 and call_addr!=0 and call_addr>=jump_to and call_addr<jump_address and verify_jump_to_instruction(instructions, jump_to):
        conditionals[2] = True
        

        #if conditionals[0]==True:
        #print("conditionals 0 is true")
    #print(conditionals)
    #print(f"Call: {call_addr}")
    #print(f"Jump: {jump_to}")
    return [True if conditionals[0] and conditionals[1] and conditionals[2] else False, 0] #usability not added yet


def test_ghidra():
    if len(sys.argv)<2:
        print("Invalid arguments\nTry: python {} binary_name_here.exe".format(__file__.split("/")[-1]))
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
        print("\nPlease set your GHIDRA_INSTALL_DIR environment variable to your ghidra installation directory\nHint: If you are on Linux, run \'which ghidra\' to find the installation directrory")
        exit()
    #Get the address of the VTABLE functions, then get the address of the call instruction,
    #Get the function start address

    #Now check for a jmp

            #Now check for a dereference in a future instruction
            #Check for proper dereferences
            #Add a normal register and a multiply arch term that need to be found
    #call_ind:int = instruction_index(instructions_readable, 'CALL')
    #print(call_ind)
    #print(instructions_readable)
    #Check if register's move instruction has [r1 + arch*r2], if so, check if that register is dereferenced before a call instruction, check if the register that is dereferencing it is being called
    #So Search for get inside the [] and see if it has 1 register + another register*arch, don't check what it is, only check what it is being moved to, then check if that is being dereferenced just with [], track all dereferences of it to see if the deref is called
    #
    #If there is a jump instruction, if it is > than the function base and < than the call, continue

def set_max_length() -> int:
    max_len:int = 30
    try:
        max_len=int(sys.argv[-1])
    except ValueError:
        print("No instruction limit set, setting it to 30")
    return max_len

def main() -> None:
    print("\n[+] Analyzing Binary...\n")
    test_ghidra()
    max_len:int = set_max_length()
    pyhidra.start()
    with pyhidra.open_program(f"{sys.argv[1]}") as bin:
        #print(type(bin))
        #Try bin.find()
        #Try bin.getBytes(adddress, pointersize)
        #IK, getReferencesTo()
        program = bin.getCurrentProgram()
        #print(type(program.getListing()))
        #breakpoint()
        manager = program.getFunctionManager()
        iterator = manager.getFunctions(True)
        func_list = []
        print("\n[+] Finding vfgadgets...\n")
        while iterator.hasNext():
            #print("NEXT")
            #FunctionDB object
            func = iterator.next()

            #print(func.getName())
            if func.isThunk():
                continue
            #if str(func.getName()).lower()!="initialize_inherited_file_handles_nolock":
            #    continue
            #get_instruction_offset(program, func.getEntryPoint()) #func.getBody())
            instructions:list[str] = list(program.getListing().getInstructions(func.getBody(), 1))

            #Saves a lot of time

            #if str(func.getName()).lower()!="fun_1400011e0":
            #    continue

            if len(instructions)>max_len:
                continue
            #if str(func.getName()).lower()!="fun_100717d5":
            #    continue
            #print(func.getName())

            #breakpoint()
            #if len(instructions>)
            #print(func)
            #print(func.getEntryPoint()) #Search the data section for this
            #print(type(func.getEntryPoint()))
            #print(program.getListing().getInstructionAt(func.getEntryPoint())) #Need address range, also only gets code
            #print(f"FUNC: {func.getBody()}")
            #print(instructions) #Need address range, also only gets code
            if (is_mlg(instructions, func.getBody(), bin)[0]):
                print(f"Potential Main Loop Gadget found at: {func.getEntryPoint()}, with the function name: {func.getName()}")
            #print(program.getListing().getCodeUnits(func.getBody())) #Need address range, also only gets code
            #print(get_disassembly(program, func))
        #print(f"PROGRAM: {program}")

if __name__=="__main__":
    main()
