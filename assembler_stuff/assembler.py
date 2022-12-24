import re
import pwn
from re import Pattern
from typing import Callable


# This bitmask is used for representing negative values
# Please change it as required
BITMASK = (2**64 - 1)

# This regex matches the form "<mnemonic>"
# This ideally is only used for nops and hlt statements
NOP_REGEX = r'([a-z]+);'

# This regex matches the form "<mnemonic> <register>;"
# Registers can be labelled as 'r<number>'
UNOP_REGEX = r'([a-z]+)\sr([0-9]*);'

# This regex matches the form "<mnemonic> <label>;"
# This is ideally only used for jumps
JMP_REGEX = r'([a-z]+)\s([a-z0-9]+);'

# This regex matches the form "<mnemonic> <register>, <register>"
BINOP_REGEX = r'([a-z]+)\sr([0-9]*),\s(0x[0-9a-fA-F]+|[0-9]+);'

# This regex matches the form ".<label>:"
# Labels can only contain alphabets
LABEL_REGEX = r'.([a-z0-9]+):'

INSN_REGEX = [NOP_REGEX, UNOP_REGEX, JMP_REGEX, BINOP_REGEX]



class Operand(object):
    _packer: Callable = None

    def __init__(self, operand: str, bits: int = 8) -> None:
        self._operand: str = operand
        self._bits: int = bits
        self._bytecode: bytes = b""

    def __str__(self) -> str:
        return f"[size={self._bits}] : {self._operand}"

    @classmethod
    def compile_operand(self, func: Callable) -> bytes:
        self._packer = func

    @staticmethod
    def basic_packer(operand_integer, bits) -> bytes:
        packer: Callable = getattr(pwn, f"p{bits}", None)
        assert packer is not None, "Could not find packing functions for operand"

        return packer(operand_integer)

    _packer = basic_packer

    def compile(self) -> bytes:
        operand_integer: int = 0

        if self._operand.startswith("0x"):
            operand_integer = int(self._operand, 16)
        else:
            operand_integer = int(self._operand)

        self._bytecode = Operand._packer(operand_integer, self._bits)

        return self._bytecode



class Instruction(object):
    _packer: Callable = None
    _unpacker: Callable = None
    _jump_identifier: Callable = None

    def __init__(self, insn: str, offset: int, *args: tuple[str]) -> None:
        self._insn_str: str = insn
        self._insn_int: int = None
        self._offset: int = offset
        self._bytecode: bytes = b""

        assert len(args) > 0, f"Error no args found for instruction {insn}"

        self.mnemonic: str = args[0]

        self._operand_strs: list[str] = []
        self._operands: list[Operand] = []

        self._label : str = ""
        self._is_label: bool = False
        self._label_fixed: bool = False

        if len(args) > 1:
            self._operand_strs = list(args)[1:]
            self._is_label = False

        self.assembled: bool = False

    def __str__(self) -> str:
        return f"[{self._offset}]: {self._insn_str} => {self._bytecode}"
    
    @property
    def offset(self) -> int:
        return self._offset
    
    @offset.setter
    def offset(self, val: int) -> None:
        assert val >= 0, f"Offset {val} is not a valid offset"
        self._offset = val
    
    @property
    def bytecode(self) -> bytes:
        return self._bytecode

    def mark_label(self) -> None:
        self._is_label = True
        self._label = self.mnemonic
        self._label_fixed = False

    @property
    def is_label(self) -> bool:
        return self._is_label
    
    @property
    def label(self) -> str:
        if self.is_label is False:
            raise Exception("Don't use the label method for non label instructions")
        return self._label

    def update_insn(self, opcode: int) -> None:
        self._insn_int = opcode

    def update_operands(self, operand_sizes: list[int]) -> None:
        self._operands = []
        assert len(self._operand_strs) == len(operand_sizes), f"Mismatch between operands and operand size list"
        x: str
        y: int
        for x, y in zip(self._operand_strs, operand_sizes):
            self._operands.append(Operand(operand=x, bits=y))

    @classmethod
    def compile_insn(self, func: Callable) -> Callable:
        self._packer = func
        return func

    @staticmethod
    def basic_packer(insn_int: int, operand_bytecode: bytes) -> bytes:
        insn_bytecode: bytes = b""
        insn_bytecode += pwn.p8(insn_int)
        return insn_bytecode + operand_bytecode

    _packer = basic_packer

    def compile(self) -> None:
        operand_bytecode: bytes = b""

        x: Operand
        for x in self._operands:
            operand_bytecode += x.compile()

        try:
            self._bytecode = Instruction._packer(self._insn_int, operand_bytecode)
        except:
            self._bytecode = b""
            return False

        self.assembled = True

    @classmethod
    def unpack_insn(self, func: Callable) -> Callable:
        Instruction._unpacker = func
        return func

    @staticmethod
    def basic_unpacker(insn: str) -> list[int]:
        raise NotImplementedError

    _unpacker = basic_unpacker

    def unpack(self):
        opcode: int = None
        operand_sizes: list[int] = []
        if self.is_label:
            opcode, _ = Instruction._unpacker('nop')
        else:
            opcode, operand_sizes = Instruction._unpacker(self.mnemonic)

        self.update_insn(opcode)
        self.update_operands(operand_sizes)

    @classmethod
    def ins_is_jump(self, func: Callable) -> Callable:
        self._jump_identifier = func
        return func

    @staticmethod
    def basic_jump_identifier(insn: str) -> bool:
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

    _jump_identifier = basic_jump_identifier

    @property
    def is_jmp(self):
        return Instruction._jump_identifier(self.mnemonic)



class Assembler:
    """The assembler class
    Currently we only support binops
    So if you want nops and/or halt statements, good luck.
    """

    def __init__(self, prog: str, insn_regexes=INSN_REGEX, label_regex=LABEL_REGEX) -> None:
        self.jump_map: dict[int, str] = {}
        self.label_indices: dict[str, int] = {}
        self.insns: list[Instruction] = []

        idx: int
        value: str
        for idx, value in enumerate(prog.strip().split("\n")):

            insn: str = value.lower()
            for insn_regex in insn_regexes:
                # Loop through 3 possible instruction regexes
                # nop, unop and binop
                pattern_match = re.match(insn_regex, insn)
                if pattern_match is not None:
                    # If some regex matches, we've succeeded
                    break

            if pattern_match is None:
                # If we reach here, it means none of the instruction regexes matched
                # its probably a label
                pattern_match = re.match(label_regex, insn)
                assert pattern_match is not None, f"Could not match instruction : {insn}"

                instruction: Instruction = Instruction(insn, idx, *pattern_match.groups())
                instruction.mark_label()
            else:
                instruction: Instruction = Instruction(insn, idx, *pattern_match.groups())

            instruction.unpack()
            self.insns.append(instruction)

    def __str__(self) -> str:
        return "\n" + "-"*10 + "\n" + "\n".join(str(x) for x in self.insns) + "\n" + "-"*10 + "\n"

    def handle_forward_jump(self, ins: Instruction, cur_idx: int, target_idx: int) -> int:
        x: Instruction
        for x in self.insns[cur_idx+1:target_idx]:
            if x.assembled is False:
                return

        target_offset: int = self.insns[target_idx].offset - ins.offset

        return target_offset

    def handle_backward_jump(self, ins: Instruction, cur_idx: int, target_idx: int) -> int:
        x: Instruction
        for x in self.insns[target_idx:cur_idx]:
            if x.assembled is False:
                return

        # When we execute this instruction, the PC will have advanced to the next instruction
        # Need to take that into account when calculating the offset
        # Therefore, include the size of the current instruction along with its offset
        cur_offset: int = ins.offset + len(ins.bytecode)

        target_offset: int = -1 * (cur_offset - self.insns[target_idx].offset)

        target_offset &= BITMASK

        return target_offset

    def handle_jump(self, ins: Instruction, cur_idx: int) -> int:
        target_label: str = ins._operand_strs[0]
        assert target_label in self.label_indices, f"Error: Label for {ins} not found in label_indices"

        target_idx: int = self.label_indices[target_label]
        target_offset: int = 0

        assert target_idx != cur_idx, "Error: Cannot handle self jumps"

        if target_idx > cur_idx:
            target_offset = self.handle_forward_jump(ins, cur_idx, target_idx)
        elif target_idx < cur_idx:
            target_offset = self.handle_backward_jump(ins, cur_idx, target_idx)
        else:
            # target_idx == cur_idx
            # The assert should've taken care of this situation
            pass

        return target_offset
    
    def assemble_insn(self, ins: Instruction, cur_idx: int, first_pass: bool = False) -> None:
        """This function is supposed to do the assembling logic
        Check if the target instruction is a jump instruction or a label

        Args:
            ins (Instruction): The instruction to assemble
        """
        if ins.is_label and first_pass is True:
            
            self.label_indices[ins.label] = cur_idx

        elif ins.is_jmp and first_pass is True:
            """
            First pass logic
            The operand of this jump instruction will be a label
            We temporarily remove this label and replace it with a unique index

            Imagine the following situation
            0: nop;
            2: l2:
            1: jmp l1;
            3: nop
            4: jmp l2;
            5: l1:
            6: nop

            In order to assemble instruction 1, we'd need to know the sizes of all instructions between 3-6 to get the correct offset.
            However, in order to assemble instruction 4, we'd need to know the sizes of all instructions from 1-4.
            This is a deadlocked condition.

            Replacing the label with a temporary offset will allow all jmp instructions to be assembled.
            The assumption here is that changing the jump offset should not change the size of the instruction.

            IF THIS ASSUMPTION IS WRONG, ALL IS LOST!
            """

            # If ins is a jump statement, its mnemonic will be the jump label
            new_idx: str = str(len(self.jump_map))
            self.jump_map[new_idx] = ins._operand_strs[0]

            # We temporarily replace the operand of the jump statement with this index
            # This will be fixed at a later point when we actually assemble jumps
            ins._operand_strs[0] = new_idx
            ins.update_operands([ins._operands[0]._bits])

        elif ins.is_jmp:
            # Not the first pass
            # Which means that we need to fix the offsets of these jump instructions

            if ins._label_fixed is False:
                # Firstly, we replace the operand of this jump instruction with the original label
                identifier: str = ins._operand_strs[0]
                assert identifier in self.jump_map, f"Error: {identifier} not found in jump_map"
                ins._operand_strs[0] = self.jump_map[identifier]
                ins.update_operands([ins._operands[0]._bits])

                # Now since I'm paranoid, I'm going to delete this entry from the dictionary
                del self.jump_map[identifier]

                ins._label_fixed = True
            
            # Now we finally assemble this instruction
            jump_offset: int = self.handle_jump(ins, cur_idx)

            # Replace the operand with the actual offset
            ins._operand_strs[0] = f"{jump_offset}"
            ins.update_operands([ins._operands[0]._bits])

        ins.compile() 
        return

    def first_pass(self) -> None:
        """The objective of this function is to assemble as many of the instructions as possible
        """
        idx: int
        ins: Instruction
        for idx, ins in enumerate(self.insns):
            self.assemble_insn(ins, idx, first_pass=True)

        # Fix offsets
        for idx in range(1, len(self.insns)):
            ins = self.insns[idx]
            prev_ins: Instruction = self.insns[idx-1]
            ins.offset = prev_ins.offset + len(prev_ins.bytecode)
    
    def assembler_pass(self) -> bool:
        """Performs a pass on the instructions and assembles them

        Returns:
            bool: True if all instructions have been assembled. False otherwise
        """
        flag: bool = True

        idx: int
        ins: Instruction
        for idx, ins in enumerate(self.insns):
            self.assemble_insn(ins, idx)

            if ins.assembled is False:
                flag = False

        for idx in range(1, len(self.insns)):
            ins = self.insns[idx]
            prev_ins: Instruction = self.insns[idx-1]
            ins.offset = prev_ins.offset + len(prev_ins.bytecode)

        return flag

    def assemble(self, debug: bool = False) -> bytes:
        """
        Logic
        1. Loop through every instruction and assemble it if possible
        2. Use a flag to determine if any instruction has not been assembled
        3. Loop until flag is false
        4. For jumps, use a dictionary to map labels to indices
        5. Replace labels with index and assemble jumps (hopefully this resolves the size issue)
        6. Once all instructions have been assembled, iterate one more time to fix jump offsets
        """

        self.first_pass()

        asm_finished: bool = False

        while asm_finished is False:
            asm_finished = self.assembler_pass()
            if debug:
                print(self)

        bytecode: bytes = b""
        ins: Instruction
        for ins in self.insns:
            bytecode += ins.bytecode

        return bytecode


