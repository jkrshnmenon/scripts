import pin


chunks = {}
d = {'AX':'RAX','BX':'RBX','CX':'RCX','DX':'RDX','DI':'RDI','SI':'RSI'}
size,start,end = 0,0,0

def isMain(addr):
	if addr >= start and addr <= end:
		return True
	else:
		return False

def is_allocated(addr):
	for x in chunks.keys():
		if x>= addr and x+chunks[x] <= addr:
			return True
	return False

def mapper(disass):
	reg = disass.split(' ')[::-1][0].upper()[1:]
	return d[reg]

def handle_write(x):
	if pin.INS_OperandIsReg(x,1):
		src = x['REG_'+mapper(x['mnemonic'])]
		m = "WRREG"
	elif pin.INS_OperandIsImmediate(x,1):
		src = pin.INS_OperandImmediate(x,1)
		m = "WRIMM"
	addr = x['MEM_OP0']
	
	if is_allocated(addr):
		e.write('{} {}\t{} MEM[{}] VAL[{}]'.format(hex(x['IP']),x['mnemonic'],m,addr,src)

def malloc_before(x):
	ret = pin.get_pointer(pin.get_pointer(x['reg_gsp']))
	if isMain(ret):
		global size
		size = x['arg_0']

def malloc_after(x):
	ret = pin.get_pointer(pin.get_pointer(x['reg_gsp']))
	if isMain(ret):
		global size
		addr = x['return']
		chunk[addr] = size
		f.write('malloc({}) => {}'.format(size,hex(addr)))

def ins_handler(ins):
	if isMain(pin.INS_Address(ins)):
		if pin.INS_IsMemoryWrite(ins):
			pin.INS_InsertCall(pin.IPOINT_BEFORE,ins,handle_write)
		elif pin.INS_IsMemoryRead(ins):
			pin.INS_InsertCall(pin.IPOINT_BEFORE,ins,handle_read)

def img_handler(img):
	if pin.IMG_IsMainExecutable(img):
		rtn = pin.RTN_FindByName(img,'malloc')
		if pin.RTN_Valid(rtn):
			pin.RTN_Open(rtn)
			pin.RTN_InsertCall(pin.IPOINT_BEFORE,'malloc',rtn,1,malloc_before)
			pin.RTN_InsertCall(pin.IPOINT_AFTER,'malloc',rtn,1,malloc_after)
			pin.RTN_Close(rtn)

def exiting():
	f.close()
	e.close()

if __name__ == "__main__":
	try:
		global start,end
		start = int(raw_input("Enter starting address of text segment"))
		end = int(raw_input("Enter ending address of text segment"))
		f = open("Allocations","w")
		e = open("Structures","w")
		pin.IMG_AddInstrumentFunction(img_handler)
		pin.INS_AddInstrumentFunction(ins_handler)
		pin.AddFiniFunction(exiting)
	except KeyboardInterrupt:
		exiting()

