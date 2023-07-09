import angr
import claripy
from pathlib import Path
from argparse import ArgumentParser
from kvm_api_ioctl import kvm_api_values


class KVMData():
    def __init__(self):
        self.kvm_api_values = kvm_api_values

        self.kvm_api_map = {}
        for x in self.kvm_api_values:
            self.kvm_api_map[self.kvm_api_values[x]] = x

    def handle_ioctl(self, fd, request, *args):
        assert request in self.kvm_api_map
        print(f"[TRAP] Got {self.kvm_api_map[request]}")

    # TODO: Handle each ioctl


handler = KVMData()


def ioctl_trap(state):
    fd = state.solver.eval(state.regs.rdi, cast_to=int)
    request = state.solver.eval(state.regs.rsi, cast_to=int)

    # TODO: Get the other args

    handler.handle_ioctl(fd, request)
    ret_val = claripy.BVS('ret_val', 64)
    state.regs.rax = ret_val


def hook_import(p, cfg):
    ioctl_plt = cfg.functions.get("ioctl")
    assert ioctl_plt is not None
    assert ioctl_plt.is_plt
    assert cfg.get_any_node(ioctl_plt.addr) is not None
    cfg_nodes = cfg.get_predecessors(cfg.get_any_node(ioctl_plt.addr))
    assert cfg_nodes is not None
    assert len(cfg_nodes) > 0
    for node in cfg_nodes:
        insn_addr = node.addr + node.block.size - 5
        if p.is_hooked(addr=insn_addr) is False:
            p.hook(addr=insn_addr, hook=ioctl_trap, length=5)


def analyze(file_path):
    p = angr.Project(file_path, auto_load_libs=False)

    # First, check if ioctl is imported from libc
    ioctl_import = p.loader.main_object.get_symbol("ioctl")
    cfg = p.analyses.CFG()
    if ioctl_import is None:
        # Syscall maybe ?
        # TODO: Find syscall locations and hook them
        raise NotImplemented
    else:
        hook_import(p, cfg)

    state = p.factory.full_init_state()
    sm = p.factory.simgr()
    sm.use_technique(angr.exploration_techniques.DFS())
    sm.run()


def create_hypervisor(result, out_file):
    pass


def compile_hypervisor(out_file):
    pass


def do_main(in_file, out_file):
    result = analyze(in_file)
    create_hypervisor(result, out_file)
    compile_hypervisor(out_file)


if __name__ == '__main__':
    parser = ArgumentParser(description="Analyze the given KVM hypervisor")
    parser.add_argument("-t", "--target", type=str, required=True, help='The path to the hypervisor')
    parser.add_argument("-o", "--output", type=str, required=False, help='The output directory for the debug version')
    args = parser.parse_args()

    target = Path(args.target)

    if not args.output:
        output = target.with_suffix(".debug")
    else:
        output = Path(args.output)

    do_main(target, output)

