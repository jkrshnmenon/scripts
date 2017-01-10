import bitstring
d = {0x0: 'mi',0x1: 'mv',0x2: 'md',0x3: 'ld',0x4: 'st',0x5: 'ad',0x6: 'sb',0x7: 'nd',0x8: 'or',0x9: 'xr',0xa: 'sr',0xb: 'sl',0xc: 'sa',0xd: 'jg',0xe: 'jl',0xf: 'jq'}

	
def parse(x):
	if x == 0x1:
		return "sp"
	elif x == 0x2:
		return "bp"
	elif x == 0x0:
		return "ip"
	elif x>= 0x3 and x <=0x7:
		return "sc"+str(x)
	elif x>=0x10 and x < 0x40:
		return "x"+hex(x).replace("0x","")
	elif x>=0x40 and x<0x100:
		return "s"+hex(x).replace("0x","")
	else:
		return hex(x)
lineno = 0
def readFile(f,insList):
	global lineno
	while True:
		num,imm = f.readlist('intle:16,intle:16')
		rm = num & 0xfff
		op = int(hex((num >> 12) & (2**4-1)),16)
		if op !=0:
			mem = parse(imm)
		rm = parse(rm)
		if op == 0xf and rm == 'ip' and mem == 'ip':
			ins = "hf"
			insList.append(hex(lineno+0x1000)+":"+ins)
			lineno+=2
			continue
		if op == 0x0 and rm == 'ip':
			ins = "ji "+hex(imm)
			insList.append(hex(lineno+0x1000)+":"+ins)
			lineno+=2
			continue
		elif op == 0x1 and rm == 'ip':
			ins = "jm "+mem
			insList.append(hex(lineno+0x1000)+":"+ins)
			lineno+=2
			continue
		ins = d[op] + " " + rm +","
		if op == 0x0:
			ins+= hex(imm)
		else:
			ins+= mem
		if op > 0xc:
			label = f.read('intle:16')
			ins+= ","+hex(label)
			lineno+=1
		insList.append(hex(lineno+0x1000)+":"+ins)
		lineno+=2

def  check_ins(insList):
	for idx,elem in enumerate(insList):
		current = elem.replace(","," ")
		nextins = insList[(idx + 1) % len(insList)].replace(","," ")
		nnextins = insList[(idx + 2) % len(insList)].replace(","," ")
		
		val1 = current.split(' ')
		val2 = nextins.split(' ')
		
		if val1[0] in ['jg','jl','jq','hf']:
			continue
		
#inc RM | dec RM
		if val1[0]=='mi' and val1[2]=='1' and val1[1]==val2[2]:
			if val2[0]=='ad':
				insList[idx] = 'inc '+val2[1]
			elif val2[0]=='sb':
				insList[idx] = 'dec '+val2[1]
			del insList[(idx+1) % len(insList)]		


		
if __name__ == '__main__':	
	f = bitstring.ConstBitStream(filename='distribute.rom')
	insList=[]
	try:
		readFile(f,insList)
	except bitstring.ReadError:
		pass
	check_ins(insList)
	for i in insList:
		print i
