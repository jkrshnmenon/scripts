import re
import pwn
from re import Pattern
from typing import Callable


INSN_REGEX = r'([a-z]+)\sr([0-9]*),\s([0-9]*);'
LABEL_REGEX = r'.([a-z]+):'


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

        return self._packer(operand_integer, self._bits)



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
        self._is_label: bool = True

        if len(args) > 1:
            self._operand_strs = list(args)[1:]
            self._is_label = False
        else:
            # Possibly a label ?
            self._label = self.mnemonic
            self._is_label = True

        self.assembled: bool = False

    def __str__(self) -> str:
        return f"[{self._offset}]: {self._insn_str} : {self._bytecode}"

    @property
    def is_label(self) -> bool:
        return self._is_label

    def update_insn(self, opcode: int) -> None:
        self._insn_int = opcode

    def update_operands(self, operand_sizes: list[int]) -> None:
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
        insn_bytecode += p8(insn_int)
        return insn_bytecode + operand_bytecode

    _packer = basic_packer

    def compile(self):
        operand_bytecode: bytes = b""
        insn_bytecode: bytes = b""

        x: Operand
        for x in self._operands:
            operand_bytecode += x.compile()

        self._bytecode = self._packer(self._insn_int, operand_bytecode)

        return self._bytecode

    @classmethod
    def unpack_insn(self, func: Callable) -> Callable:
        self._unpacker = func
        return func

    @staticmethod
    def basic_unpacker(insn: str) -> list[int]:
        raise NotImplementedError
        return 0, []

    _unpacker = basic_unpacker

    def unpack(self):
        opcode: int = None
        operand_sizes: list[int] = None
        if self.is_label:
            opcode, _ = self._unpacker('nop')
        else:
            opcode, operand_sizes = self._unpacker(self.mnemonic)

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
        return self._jump_identifier(self.mnemonic)



class Assembler:
    def __init__(self, prog: str, insn_regex=INSN_REGEX, label_regex=LABEL_REGEX) -> None:
        self.insns: list[Instruction] = []

        idx: int
        insn: str
        for idx, insn in enumerate(prog.strip().split("\n")):
            pattern_match = re.match(insn_regex, insn)
            if pattern_match is None:
                pattern_match = re.match(label_regex, insn)
                assert pattern_match is not None, f"Could not match instruction : {insn}"

            instruction: Instruction = Instruction(insn, idx, pattern_match.groups())
            instruction.unpack()
            self.insns.append(instruction)

    def __str__(self) -> str:
        return "\n" + "-"*10 + "\n" + "\n".join(str(x) for x in self.insns) + "\n" + "-"*10 + "\n"

    def find_label_idx(self, label):
        for idx, ins in enumerate(self.insns):
            if ins.is_label is False:
                continue
            if ins.label == label:
                return idx

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

        cur_offset: int = self.insns[cur_idx-1].offset + len(self.insns[cur_idx-1].bytecode)
        target_offset: int = -1 * ((cur_offset + 8 + 1) - self.insns[target_idx].offset)

        target_offset &= (2**64 - 1)

        return target_offset

    def handle_jump(self, ins: Instruction, cur_idx: int) -> int:
        target_idx: int = self.find_label_idx(ins.label)
        target_offset: int = 0
        if target_idx > cur_idx:
            target_offset = self.handle_forward_jump(ins, cur_idx, target_idx)
        else:
            target_offset = self.handle_backward_jump(ins, cur_idx, target_idx)

        return target_offset

    def compile_insn(self, ins: Instruction, cur_idx: int):
        if ins.is_jmp:
            target_offset: int = self.handle_jump(ins, cur_idx)
            ins.operands = [hex(target_offset)]

        ins.compile()
        ins.assembled = True

    def assembler_pass(self) -> bool:
        flag: bool = True
        idx: int
        ins: Instruction
        for idx, ins in enumerate(self.insns):
            if ins.assembled is False:
                self.compile_insn(ins, idx)
                if ins.assembled is False:
                    flag = False
                elif idx > 0:
                    prev_ins: Instruction = self.insns[idx-1]
                    ins.offset = prev_ins.offset + len(prev_ins.bytecode)

        return flag

    def assemble(self, debug: bool = False) -> bytes:
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



