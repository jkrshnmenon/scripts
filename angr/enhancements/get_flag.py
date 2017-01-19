import angr,claripy

class get_flag:
	def __init__(self,filename,load_opts):
		self.p = angr.Project(filename,load_options = load_opts)
		self.d = {'plt.printf':0,'plt.puts':0,'plt.write':0}
		self.positives = ['Nice',' flag','Flag',' nice',' correct',' got it']
		self.candidates = []
		self.result = []
		self.cfg = self.p.analyses.CFGAccurate()
		for address,function in self.cfg.functions.iteritems():
			if function.is_plt:
				if function.name in self.d.keys():
					self.d[function.name] = address
				continue
			elif function.is_syscall or function.is_simprocedure:
				continue
			if self.function_references_flag(function):
				call_sites = self.writes_to_stdout(function)
				for x in call_sites:
					if x >= self.p.entry and self.node_references_flag(x,function):
						node = self.cfg.get_any_node(x)
						self.candidates.append(node)

		self.candidates.sort(key=lambda x: self.get_predecessor_length(x))

	def writes_to_stdout(self,function):
		call_sites = function.get_call_sites()
		ret = []
		if len(call_sites) <=0:
			return False
		for x in call_sites:
			target = function.get_call_target(x)
			for key in self.d.keys():
				if self.d[key] == target:
					ret.append(x)
		return ret

	def get_chain_length(self,node):
		return 0
	
	def get_predecessor_length(self,node):
		predecessor = node.predecessors
		return len(predecessor)
	
	def function_references_flag(self,function):
		references = function.string_references()
		for x in references:
			for y in self.positives:
				if y in x[1]:
					return True
	
	def node_references_flag(self,block,function):
		references = function.string_references()
		block = self.p.factory.block(block)
		for ins in block.capstone.insns:
			if ins.insn.insn_name() == 'mov' and ins.insn.operands[1].type == 2:
				target = ins.insn.operands[1].imm
				for x in references:
					if x[0] == target:
						for y in self.positives:
							if y in x[1]:
								return True
		return False
				
	
	def get_candidates(self):
		return self.candidates

	def get_paths(self):
		for x in self.candidates:
			pg = self.p.factory.path_group()
			pg.explore(find=x.addr)
			for pp in pg.found:
				self.result.append(pp)
		return self.result
