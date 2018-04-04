from pwn import *

logging.basicConfig(filename='stats.log')
logger = logging.getLogger('pivot_logger')
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler('stats.log')
handler.setLevel(logging.INFO)
logger.addHandler(handler)


class Pivot:
    def __init__(self, ret_addr, offset, elf=None, target=None):
        self.ret_addr = ret_addr
        self.offset = offset
        if self.elf is None and self.target is None:
            raise TargetException("Provide either the ELF or target address")
        self.target = self.get_addr() if target is None else target

    def get_addr(self):
        if self.elf.pie is True:
            raise TargetException("Cannot detect pivot target. PIE is enabled")
        bss_base = self.elf.bss() & ~4095
        return bss_base + 1024

    def get_payload():
        logger.info('Pivoting stack to {}'.format(hex(self.target)))
        if self.elf.bits == 32:
            packer = p32
        elif self.elf.bits == 64:
            packer = p64
        payload = fit({offset: packer(self.target)+packer(self.ret_addr)})
        return payload


class TargetException(Exception):
    def __init__(self, value):
        self.value = value
