import angr,claripy

class get_flag:
	def __init__(self,filename,load_opts):
		self.p = angr.Project(filename,load_options = load_opts)
		self.d = {'plt.printf':0,'plt.puts':0,'plt.write':0}
		self.candidates = []
		self.results = []
		self.cfg = self.p.analyses.CFGAccurate()
		for address,function in self.cfg.functions.iteritems():
			if function.is_plt:
				if function.name in self.d.keys():
					self.d[function.name] = address
				continue
			elif function.is_syscall or function.is_simprocedure:
				continue
			call_sites = function.get_call_sites()
			if len(call_sites) <=0:
				continue
			if self.writes_to_stdout(call_sites,function) and self.references_flag(function):
				for x in call_sites:
					if x >= self.p.entry:
						node = cfg.get_any_node(x)
							self.candidates.append(node)
		for x in self.candidates:
			pg = self.p.factory.path_group()
			pg.explore(find = x.addr)
			for pp in pg.found:
				self.results.append(pp)
		return pp

	def writes_to_stdout(self,call_sites,function):
		for x in call_sites:
			target = function.get_call_target(x)
			for key in self.d.keys():
				if self.d[key] == target:
					return True

	def get_chain_length(self,node):
		
	
	def get_predecessor_length(self,node):
		predecessor = node.predecessors
		return len(predecessor)
	
	def references_flag(self,function):
		references = function.string_references()
		for x in references:
			if 'flag' in x[1]:
				return True

