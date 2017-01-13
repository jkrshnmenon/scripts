import angr
p=angr.Project("a2b",load_options={'auto_load_libs':False})
s=p.factory.entry_state()
for x in xrange(30):
    k=s.posix.files[0].read_from(1)
    s.se.add(k >= 0x20)
    s.se.add(k <='{')
k=s.posix.files[0].read_from(1)
s.se.add(k == 10)
s.posix.files[0].seek(0)
s.posix.files[0].length = 31
pg =p.factory.path_group(s)
pg.run()
out=""
for x in xrange(len(pg.deadended)):
    out=pg.deadended[x].state.posix.dumps(1)
    if 'flag' in out:
	break
print pg.deadended[x].state.posix.dumps(0)
