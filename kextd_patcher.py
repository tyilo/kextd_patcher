#!/usr/bin/env python
import sys
import os
import shutil
import tempfile
import re
import r2pipe
import itertools
import subprocess

def get_error_cfxrefs(r2):
	r2.cmd('aa')
	r2.cmd('ac 2> /dev/null')

	# Work around r2 bug, making r2 search from a very low vaddr
	r2.cmd('e search.from = 0x100000000')

	error_cstring = int(r2.cmd('/ ERROR 2> /dev/null').split(' ')[0], base=0)
	error_cxref = int(r2.cmd('/v {} 2> /dev/null'.format(error_cstring)).split(' ')[0], base=0)

	error_cfstring = error_cxref - 0x10

	error_cfxrefs = r2.cmd('axt {} 2> /dev/null'.format(error_cfstring)).strip().split('\n')

	if error_cfxrefs[0] == '':
		error_cfxrefs = []

	return error_cfxrefs

f = tempfile.NamedTemporaryFile(delete=False)
f.close()

shutil.copy2('/usr/libexec/kextd', f.name)

r2 = r2pipe.open(f.name, writeable=True, bits=64)

print 'Analyzing kextd binary...'

error_cfxrefs = get_error_cfxrefs(r2)

if len(error_cfxrefs) == 0:
	print 'Found 0 xrefs to ERROR CFString.'
	print 'Is your kextd already patched?'
	os.remove(f.name)
	sys.exit(1)

print 'Found {} xrefs to ERROR CFString.'.format(len(error_cfxrefs))

for xref in error_cfxrefs:
	error_cfxref = int(xref.split(' ')[1], base=0)

	for i in itertools.count():
		result = r2.cmd('axt {}'.format(error_cfxref - i))
		if result != '':
			break

	conditional_jump = int(result.split(' ')[1], base=0)
	should_nop_jump = True

	basic_block_start = error_cfxref - i

	dis = r2.cmd('e asm.esil=true; pD {} @ {}'.format(i, basic_block_start))

	conditional_jumps = re.findall(r'(0x[0-9a-f]+).*\?\{[^}]*rip[^}]*\}', dis)

	if len(conditional_jumps) > 0:
		last_conditional_jump = int(conditional_jumps[-1], base=0)
		if last_conditional_jump > basic_block_start:
			conditional_jump = last_conditional_jump
			should_nop_jump = False

	jump_size = int(r2.cmd('pdl 1 @ {}'.format(conditional_jump)))
	nop_location = conditional_jump
	nops_required = jump_size

	if not should_nop_jump:
		jump_location = int(r2.cmd('axf @ {}'.format(conditional_jump)).split(' ')[3], base=0)
		print 'Location: {:x}'.format(jump_location)

		arch = r2.cmd('e asm.arch').strip()
		bits = r2.cmd('e asm.bits').strip()

		output = subprocess.check_output(['rasm2', '-a', arch, '-b', bits, '-o', str(conditional_jump), 'jmp {}'.format(jump_location)]).strip()
		new_jump_size = len(output) / 2
		if new_jump_size > jump_size:
			print 'Error couldn\'t replace conditional jump with unconditional one:'
			print 'Bytes available: {}, needed: {}'.format(jump_size, new_jump_size)
			sys.exit(1)

		r2.cmd('wx {} @ {}'.format(output, conditional_jump))

		nop_location = conditional_jump + new_jump_size
		nops_required = jump_size - new_jump_size

	for i in range(nops_required):
		r2.cmd('wa nop @ {}'.format(nop_location + i))

	print 'Patched conditional jump at 0x{:x} with {}'.format(conditional_jump, 'nops' if should_nop_jump else 'an unconditional jump')


print 'Verifying that patch was successful...'

r2 = r2pipe.open(f.name, bits=64)

new_error_cfxrefs = get_error_cfxrefs(r2)
if len(new_error_cfxrefs) > 0:
	print 'Failed to remove all xrefs, there are {} remaining:'.format(len(new_error_cfxrefs))
	print '\n'.join(new_error_cfxrefs)
	os.remove(f.name)
	sys.exit(1)

print 'Patch was successful!'

print 'Removing code signature...'
subprocess.check_call(['ldid', '-S', f.name])

print 'Patched file is located at: {}'.format(f.name)
