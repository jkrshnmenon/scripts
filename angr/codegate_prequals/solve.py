import angr

p = angr.Project('angrybird',load_options={'auto_load_libs':False})
cfg = p.analyses.CFGAccurate()
f = cfg.functions.function(0x400761)
s = p.factory.blank_state(addr=0x4007da)
flag = s.se.BVS('flag',0x20*8)
s.memory.store(s.regs.rbp-0x70,s.se.BVV(0x606018,64))
s.memory.store(s.regs.rbp-0x68,s.se.BVV(0x606020,64))
s.memory.store(s.regs.rbp-0x60,s.se.BVV(0x606028,64))
s.memory.store(s.regs.rbp-0x58,s.se.BVV(0x606038,64))
s.memory.store(s.regs.rbp-0x50,flag)
for address,function in cfg.functions.iteritems():
	if 'puts' in function.name:
		puts = function
		break
call_sites = f.get_call_sites()
avoids = []
for x in call_sites:
	target = f.get_call_target(x)
	if puts.addr == target:
		avoids.append(x)
pg = p.factory.path_group(s)
pg.explore(find=0x404fc1,avoid = avoids)
for p in pg.found:
	print p.state.posix.dumps(1)
