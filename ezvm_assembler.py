import ipdb
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


class Instruction:
    def __init__(self, insn: str, offset: int) -> None:
        self.insn = insn
        self.label = ""
        self.offset = offset
        self.bytecode = b""
        self._is_jmp = False
        self._is_label = False
        self.assembled = False

        if self.insn.startswith("."):
            self.init_label()
        else:
            self.init_ins()

    def init_label(self):
        self._is_label = True
        self.opcode = "nop"
        self.operands = []
        self.label = self.insn.strip()

    def init_ins(self):
        self.opcode = self.insn.split(" ")[0]

        assert self.opcode in ARG_MAP, f"{self.opcode} not in ARG_MAP"

        self.operands = self.insn.split(" ")[1:]

        assert len(self.operands) == len(ARG_MAP[self.opcode])

        if self.opcode in ["jmp", "jz", "jnz"]:
            self._is_jmp = True
            self.label = self.operands[0]


    def __str__(self) -> str:
        return f"[{self.offset}]: {self.insn} : {self.bytecode}"

    @property
    def opcode_c(self):
        return p8(INS_MAP[self.opcode])

    @property
    def operands_c(self):
        bytecode = b""
        for idx, sz in enumerate(ARG_MAP[self.opcode]):
            if sz == 1:
                if self.operands[idx].startswith("r"):
                    bytecode += p8(int(self.operands[idx][1:]))
                else:
                    bytecode += p8(int(self.operands[idx]))
            elif sz == 8:
                if self.operands[idx].startswith("0x"):
                    bytecode += p64(int(self.operands[idx], 16))
                else:
                    bytecode += p64(int(self.operands[idx]))

        return bytecode

    @property
    def is_jmp(self):
        return self._is_jmp

    @property
    def is_label(self):
        return self._is_label


class Assembler:
    def __init__(self, insns):
        self.insns = []
        insns = insns.strip().split("\n")
        for idx, insn in enumerate(insns):
            self.insns.append(Instruction(insn, idx))

    def __str__(self) -> str:
        return "\n" + "-"*10 + "\n" + "\n".join(str(x) for x in self.insns) + "\n" + "-"*10 + "\n"

    def find_label_idx(self, label):
        for idx, ins in enumerate(self.insns):
            if ins.is_label is False:
                continue
            if ins.label == label:
                return idx

    def compile_insn(self, ins, cur_idx):
        if ins.is_jmp:
            target_idx = self.find_label_idx(ins.label)
            if target_idx > cur_idx:
                for x in self.insns[cur_idx+1:target_idx]:
                    if x.assembled is False:
                        return
                target_offset = self.insns[target_idx].offset - ins.offset
            else:
                for x in self.insns[target_idx:cur_idx]:
                    if x.assembled is False:
                        return
                cur_offset = self.insns[cur_idx-1].offset + len(self.insns[cur_idx-1].bytecode)
                target_offset = -1 * ((cur_offset + 8 + 1) - self.insns[target_idx].offset)
                if target_offset < 0:
                    target_offset &= (2**64 - 1)
            ins.operands = [hex(target_offset)]
            
        ins.bytecode =  ins.opcode_c + ins.operands_c
        ins.assembled = True

    def assembler_pass(self) -> bool:
        flag = True
        for idx, ins in enumerate(self.insns):
            if ins.assembled is False:
                self.compile_insn(ins, idx)
                if ins.assembled is False:
                    flag = False
                elif idx > 0:
                    prev_ins = self.insns[idx-1]
                    ins.offset = prev_ins.offset + len(prev_ins.bytecode)

        return flag

    def assemble(self, debug=False) -> bytes:
        asm_finished = False

        while asm_finished is False:
            asm_finished = self.assembler_pass()
            if debug:
                print(self)

        bytecode = b""
        for ins in self.insns:
            bytecode += ins.bytecode
        return bytecode


if __name__ == '__main__':
    PROG = """
nop
jmp .l1
push r1
.l1
pop r2
"""
    assembler = Assembler(PROG)
    bytecode = assembler.assemble(debug=True)
    print(bytecode)
