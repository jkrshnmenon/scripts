def get_arch():
    return gdb.selected_frame().architecture().name()

def get_memory(addr, size_str):
    out = gdb.execute(f"x/{size_str}x {addr}", to_string=True)
    return out.strip().split(":\t")[1]

def get_byte(addr):
    return get_memory(addr, "b")

def get_word(addr):
    return get_memory(addr, "h")

def get_dword(addr):
    return get_memory(addr, "w")

def get_qword(addr):
    return get_memory(addr, "g")

def get_func():
    out = gdb.execute("x/i $pc", to_string=True).split("<")[1].split(">")[0].strip()
    return out

def get_symbol(sym_name):
    out = gdb.execute(f"p/x &{sym_name}", to_string=True).strip().split()[-1]

def get_reg(reg_name):
    out = gdb.execute(f"i r {reg_name}", to_string=True)
    assert len(out.split()) > 2, f"Error in getting register {reg_name} : {out}"
    return out.split()[1]

def get_ins():
    out = gdb.execute(f"x/i $pc", to_string=True)
    return out.strip().split(":\t")[1]

def calc(equation):
    out = gdb.execute(f"p/x {equation}", to_string=True)
    return out.strip().split()[-1]
