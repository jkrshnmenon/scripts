import angr,claripy

def phase_1():
	s = p.factory.blank_state(addr=0x08048b2c)
	val = s.se.BVS('val',30*32)
	s.memory.store(0x804bd10,val)
	s.regs.eax = s.se.BVV(0x804bd10,32)
	pg = p.factory.path_group(s)
	pg.explore(find=0x08048b43,avoid=0x08048b3e)
	if len(pg.found) > 0:
		print "Finished phase 1"
		state = pg.found[0].state
		return state.se.any_str(val)

def phase_2():
	val = []
	s = p.factory.blank_state(addr=0x8048b63)
	for x in range(6):
		s.memory.store(s.regs.ebp-0x18+(x*4),s.se.BVS('int{}'.format(x),32))
	pg = p.factory.path_group(s)
	pg.explore(find=0x08048b8e,avoid =(0x08048b69,0x08048b83))
	if len(pg.found)>0:
		print "Finished phase 2"
		s=pg.found[0].state
		for x in range(6):
			val.append(s.se.any_int(s.memory.load(s.regs.ebp-0x18+(x*4),2,endness='Iend_LE')))
	return val

def phase_3():
	s = p.factory.blank_state(addr=0x08048bc9)
	s.memory.store(s.regs.ebp-0xc,s.se.BVS('x',32))
	s.memory.store(s.regs.ebp-0x5,s.se.BVS('y',8))
	s.memory.store(s.regs.ebp-0x4,s.se.BVS('z',32))
	pg = p.factory.path_group(s)
	pg.explore(find=0x08048c99,avoid=(0x08048bef,0x08048c0f,0x08048c21,0x08048c33,0x08048c4b,0x08048c5d,0x08048c6f,0x08048c81,0x08048c8a,0x08048c94))
	if len(pg.found)>0:
		print "Finished phase 3"
		s = pg.found[0].state
		val=[]
		val.append(s.se.any_int(s.memory.load(s.regs.ebp-0xc,1,endness="Iend_LE")))
		val.append(s.se.any_str(s.memory.load(s.regs.ebp-0x5,1,endness="Iend_LE")))
		val.append(s.se.any_int(s.memory.load(s.regs.ebp-0x4,1,endness="Iend_LE")))
	return val

if __name__ == "__main__":
	p = angr.Project("bomb",load_options={'auto_load_libs':False})
	print phase_1()
	results = phase_2()
	for x in results:
		print x
	results = phase_3()
	for x in results:
		print x
