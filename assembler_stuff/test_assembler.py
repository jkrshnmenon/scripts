from assembler import *
from pwn import p8, p64

ARG_MAP = {
        "push": [1],
        "pop": [1],
        "sub": [],
        "shr": [],
        "and": [],
        "jmp": [8],
        "jnz": [8],
        "jz": [8],
        "eq": [],
        "gt": [],
        "lt": [],
        "li": [1, 8],
        "sq": [1, 8],
        "lq": [1, 8],
        "hlt": [],
        "nop": [],
}


INS_MAP = {
        "push": 0,
        "pop": 1,
        "sub": 3,
        "shr": 8,
        "and": 9,
        "jmp": 14,
        "jnz": 15,
        "jz": 16,
        "eq": 17,
        "gt": 18,
        "lt": 19,
        "li": 20,
        "sq": 21,
        "lq": 22,
        "hlt": 23,
        "nop": 24,
}


@Operand.compile_operand
def do_compile_operand(op_int, bit_len) -> bytes:
    # Pack the operand with value op_int into a value that contains bit_len bits
    if bit_len == 8:
        return p8(op_int)
    elif bit_len == 64:
        return p64(op_int)
    
    # Should not be triggered
    raise NotImplementedError

@Instruction.unpack_insn
def do_unpack_insn(mnemonic) -> tuple[int, list[int]]:
    # Return the opcode value (int) and a list of operand sizes (in bits) for this mnemonic
    return INS_MAP[mnemonic], list(map(lambda x: x*8, ARG_MAP[mnemonic]))

@Instruction.ins_is_jump
def do_ins_is_jump(mnemonic) -> bool:
    # This function is supposed to return true if the mnemonic corresponds to a jump instruction
    # False otherwise
   return insn in ['jmp',
                   'jeq',
                   'jne',
                   'jz',
                   'jnz',
                   'jl',
                   'jle',
                   'jg',
                   'jge',
                   'jb',
                   'jbe',
                   'ja',
                   'jae',
                   ]

@Instruction.compile_insn
def do_compile_insn(opc_int, operand_bytes) -> bytes:
    # Pack the instruction with opcode opc_int and the operands (which have already een assembled into operand_bytes)
    return p8(opc_int) + operand_bytes


if __name__ == '__main__':
    PROG = """
nop;
jmp l1;
push r1;
.l1:
pop r2;
"""
    import ipdb; ipdb.set_trace()
    assembler = Assembler(PROG)
    bytecode = assembler.assemble(debug=True)
    print(bytecode)
