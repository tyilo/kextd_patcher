#!/usr/bin/env python
import sys
import os
import shutil
import tempfile
import r2pipe
import subprocess
import json

f = tempfile.NamedTemporaryFile(delete=False)
f.close()

shutil.copy2('/usr/libexec/kextd', f.name)

r2 = r2pipe.open(f.name, writeable=True, bits=64)

out = subprocess.check_output(['rabin2', '-j', '-i', '/usr/libexec/kextd'])
data = json.loads(out)
imports = data['imports']

needs_patching = filter(
	lambda x: x['name'].startswith('SecStaticCodeCheckValidity'),
	imports
)

for fun in needs_patching:
	r2.cmd('s {}'.format(fun['plt']))
	r2.cmd('"wa xor eax, eax; ret"')

	print 'Patched {}'.format(fun['name'])

print 'Removing code signature...'
subprocess.check_call(['ldid', '-S', f.name])

print 'Patched file is located at: {}'.format(f.name)
