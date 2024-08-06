import pyhidra
import sys
import os
import jpype

#Remember to add XFG option

common_vtable_registers:list[str] = ["ax", "cx", "dx", "bx"]

jump_instructions:list[str] = ["jmp", "jne", "je", "jo", "jno", "js", "jns", "jz", "jnz", "jb", "jnae", "jnb", "jc", "jae", "jnc", "jbe", "jna", "ja", "jnbe", "jl", "jnge", "jge", "jnl", "jle", "jg", "jnle", "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz"]

#Look for a virtual function calling other virtual functions in a loop, get its location in the vtable and get the vtable address
#Pass a disassembled ghidra function in the argument

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
    
def is_mlg(instructions:list, addr_set) -> [bool, int]:
    #Find the VTABLE where the start of the function base is mentioned
    instructions_readable = convert_to_str_list(instructions)
    if "ret" not in instructions_readable[-1].lower():
        return [False, 0]
    if instruction_ind_reg(instructions_readable, 'CALL')==-1: #Make it contain a register
        return [False, 0]        

    #1: Is there a VTABLE call?
    #2: Is the jump after the call and does it go before the call, is it within the function?
    #3 (Bonus): Is the call protected by CFG?
    conditionals:list[bool] = [False, False]
    usability:int = 0

    modified_regs:list = []
    call_regs:list = []
    vtable_indexes = []
    call_indexes = []
    
    for ind, instr in enumerate(instructions_readable):
        start_ind = instr.find("[")
        end_ind = instr.find("]")
        if start_ind>-1 and end_ind>-1:
            drefin_instr:str = instr[start_ind+1:end_ind]
            dref_sp:list[str] = drefin_instr.split(" ")
            deref_markers = 0
            for dind, deref in enumerate(dref_sp):
                if len(deref)==3 and '0x' not in deref: #esp+0x3
                    deref_markers +=1
                elif '*' in deref:
                    deref_markers += 1
            if deref_markers==2:
                modified_regs.append(instr.split(" ")[1].split(",")[0].lower())
                vtable_indexes.append(ind)
                
    for i in vtable_indexes:
        for ind, instr in enumerate(instructions_readable[i:], start=i):
            start_ind = instr.find("[")
            end_ind = instr.find("]")
            if start_ind>-1 and end_ind>-1:
                for modified_reg in modified_regs:
                    if len(instr[start_ind+1:end_ind])==3 and instr[start_ind+1:end_ind].lower()==modified_reg:
                        call_regs.append(instr.split(" ")[1].split(",")[0])
                        call_indexes.append(ind)

    for i in call_indexes: #what about guard check?
        for ind, instr in enumerate(instructions_readable[i:], start=i):
            if len(instr.split(" ")) >0 and instr.split(" ")[0].lower()=="call":
                for reg in call_regs:
                    if instr.split(" ")[1]==reg:
                        conditionals[0] = True

    for i in instructions_readable:
        for j in jump_instructions:
            if i.split(" ")[0].lower()==j:
                if int(i.split(" ")[1], 16)>=int("0x"+str(addr_set).split(',')[0][2:], 16) and int(i.split(" ")[1], 16)<=int("0x"+str(addr_set).split(' ')[1][1:-1], 16):
                    conditionals[1] = True
                    
    return [True if conditionals[0] and conditionals[1] else False, 0] #usability not added yet

def test_ghidra():
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
        print("Please set your GHIDRA_INSTALL_DIR environment variable to your ghidra installation directory\nHint: If you are on Linux, run \'which ghidra\' to find the installation directrory")
        exit()

def main() -> None:
    print("This is an experimental version of V++. Currently, this script has limited functionality. Please check the repository for updates.")
    test_ghidra()
    pyhidra.start()
    with pyhidra.open_program(f"{sys.argv[1]}") as bin:
        program = bin.getCurrentProgram()
        manager = program.getFunctionManager()
        iterator = manager.getFunctions(True)
        func_list = []
        while iterator.hasNext():
            func = iterator.next()
            instructions:list[str] = list(program.getListing().getInstructions(func.getBody(), 1))
            if (is_mlg(instructions, func.getBody())[0]):
                print(f"Main Loop Gadget found at: {func.getEntryPoint()}")

if __name__=="__main__":
    main()
