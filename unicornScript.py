from unicorn import *
from unicorn.x86_const import *
import pefile
from capstone import *
from termcolor import colored
import struct

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class emulator:

	def __init__(self, stackAddr=0xf000000, stackSize = 0x2000, mode=32, binary=None):	
		self.stackAddr = stackAddr
		self.stackSize = stackSize
		self.mode = mode
		if (mode == 32):
			self.arch = UC_ARCH_X86
			self.mode = UC_MODE_32
			self.disass = Cs(CS_ARCH_X86, CS_MODE_32)
		elif (mode == 64):
			self.arch = UC_ARCH_X86
			self.mode = UC_MODE_64
			self.disass = Cs(CS_ARCH_X86, CS_MODE_64)
		else: 
			print("[x] Invalid mode")
			exit(0)
		self.uc = Uc(self.arch, self.mode)
		if (binary != None):
			self.setEmulatorBinary(binary)
	
	def resetEmu():
		self.uc.mem_unmap(self.ImageBase, self.pef.OPTIONAL_HEADER.SizeOfImage)
		uc_close(self.uc)		
	
	def resetMode(mode):
		if mode not in [32, 64]:
			print ("[x] Invalid mode")
			return
		resetEmu()
		if (mode == 32):
			self.arch = UC_ARCH_X86
			self.mode = UC_MODE_32
			self.disass = Cs(CS_ARCH_X86, CS_MODE_32)
		elif (mode == 64):
			self.arch = UC_ARCH_X86
			self.mode = UC_MODE_64
			self.disass = Cs(CS_ARCH_X86, CS_MODE_64)			
			
	### IMPORT INFO
	def IATHook(self):
		self.apiThunk = []
		self.pef.parse_data_directories(directories = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'])
		for importDirectoryEntry in self.pef.DIRECTORY_ENTRY_IMPORT:
			parsedImport = self.pef.parse_imports(importDirectoryEntry.struct.Characteristics, importDirectoryEntry.struct.FirstThunk, importDirectoryEntry.struct.ForwarderChain)
			for pImport in parsedImport:
				if (not pImport.hint_name_table_rva is None):
					self.apiThunk.append( (hex(pImport.address), hex(pImport.thunk_offset), self.pef.get_string_at_rva(pImport.hint_name_table_rva + 2), importDirectoryEntry.dll) )
		print (self.apiThunk)
	### EMULATE
	def setEmulatorBinary(self, binary):
		pef = pefile.PE(binary)
		if (pef.OPTIONAL_HEADER.Magic == 0x20b):
			if (self.mode == 32):
				print ("[x] 64-bit Image but 32-bit emu")
				return
		elif (pef.OPTIONAL_HEADER.Magic == 0x10b):
			if (self.mode == 64):
				print ("[x] 32-bit Image but 64-bit emu")
				return
		
		# Stack Mapping
		self.uc.mem_map(self.stackAddr, self.stackSize + 0x1000)
				
		# Binary Mapping
		self.binary = binary
		self.pef = pef
		self.ImageBase = self.pef.OPTIONAL_HEADER.ImageBase
		print("[!] Emu Binary Image Base: 0x%x" % self.ImageBase)
		self.pef.full_load()
		self.uc.mem_map(self.ImageBase, self.pef.OPTIONAL_HEADER.SizeOfImage)
		self.uc.mem_write(self.ImageBase, pef.get_memory_mapped_image())
		self.uc.mem_protect(self.ImageBase, self.pef.OPTIONAL_HEADER.SizeOfImage, 7)
		self.uc.hook_add(UC_HOOK_BLOCK, self.hook_block)
		self.uc.hook_add(UC_HOOK_CODE, self.hook_code)
		# self.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self.hook_fetch_unmapped)
		
		if (self.mode == UC_MODE_32):
			self.uc.reg_write(UC_X86_REG_ESP, self.stackAddr + 0x1000)
		else:
			self.uc.reg_write(UC_X86_REG_RSP, self.stackAddr + 0x1000)
		self.IATHook()	
		
	##### Hook List
	def hook_block(self, uc, address, size, user_data):
		# print("\n---------------------------------->>> Tracing block at 0x%s, size = 0x%s <<<----------------------------------\n" %(hex(address)[2:].rjust(16, '0'), hex(size)[2:].rjust(4,'0')))
		return

	def hook_code(self, uc, address, size, user_data):
		inst = list(self.disass.disasm(self.uc.mem_read(address, size), 9))[0]
		print((">>> 0x%x: %s %s" % (address, inst.mnemonic, inst.op_str)).ljust(60, ' '), end=' ')
		if self.mode == UC_MODE_32:
			print ("Reg: eax = 0x%x, ebx = 0x%x, ecx = 0x%x, edx = 0x%x, esi = 0x%x, edi = 0x%x, ebp = 0x%x, esp = 0x%x" % (  
				self.uc.reg_read(UC_X86_REG_EAX),
				self.uc.reg_read(UC_X86_REG_EBX),
				self.uc.reg_read(UC_X86_REG_ECX),
				self.uc.reg_read(UC_X86_REG_EDX),
				self.uc.reg_read(UC_X86_REG_ESI),
				self.uc.reg_read(UC_X86_REG_EDI),
				self.uc.reg_read(UC_X86_REG_EBP),
				self.uc.reg_read(UC_X86_REG_ESP))
				)
			print ("\tStack: ", end='')
			
			stackMem = self.uc.mem_read(self.uc.reg_read(UC_X86_REG_ESP), 40)
			print (" ".join(hex(struct.unpack("<I", stackMem[i:i+4])[0]) for i in range(0, 40, 4)), end = "\n\n")
			
		elif self.mode == UC_MODE_64:
			print ("Reg: rax = 0x%x, rbx = 0x%x, rcx = 0x%x, rdx = 0x%x, rsi = 0x%x, rdi = 0x%x, rbp = 0x%x, rsp = 0x%x, r8 = 0x%x, r9 = 0x%x, r10 = 0x%x" % (  
				self.uc.reg_read(UC_X86_REG_RAX),
				self.uc.reg_read(UC_X86_REG_RBX),
				self.uc.reg_read(UC_X86_REG_RCX),
				self.uc.reg_read(UC_X86_REG_RDX),
				self.uc.reg_read(UC_X86_REG_RSI),
				self.uc.reg_read(UC_X86_REG_RDI),
				self.uc.reg_read(UC_X86_REG_RBP),
				self.uc.reg_read(UC_X86_REG_RSP),
				self.uc.reg_read(UC_X86_REG_R8),
				self.uc.reg_read(UC_X86_REG_R9),
				self.uc.reg_read(UC_X86_REG_R10))				
				)
			print ("\tStack: ", end='')
			
			stackMem = self.uc.mem_read(self.uc.reg_read(UC_X86_REG_ESP), 80)
			print (" ".join(hex(struct.unpack("<I", stackMem[i:i+8])[0]) for i in range(0, 80, 8)), end = "\n\n")
	
	# def hook_fetch_unmapped (self, uc, address, size, user_data):
		# print (">>> UNMAPPED ADDRESS !!! 0x%x", hex(address)[2:].rjust(16, '0'))
		
	#### End Hook List
	def setReg(self, reg, val):
		self.uc.reg_write(reg, val)
	
	def emulate(self, startAddr, endAddr):
		self.uc.emu_start(startAddr, endAddr)
		
		

if __name__ == "__main__":
	emu = emulator(mode=32)
	emu.setEmulatorBinary("E:\\Malware\\Tuts 4 You UnpackMe Collection (2016)\\PE32 x32\\VMProtect 1.1\\UnPackMe_VMProtect 1.1.exe")
	emu.setReg(UC_X86_REG_EAX, 0x100)
	emu.setReg(UC_X86_REG_EDX, 0x46B000)
	emu.setReg(UC_X86_REG_ESI, 0x4729E7)
	# emu.emulate(0x004271B0, 0)
	emu.emulate(0x046FBAC, 0)
	
		