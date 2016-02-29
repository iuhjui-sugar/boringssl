#!/usr/bin/python
import os
import subprocess
import sys

def is_asm(l):
  l = l.strip()
  return not (l == '' or l.startswith('#') or l.startswith('.') or l.endswith(':'))

def merge(cgs, srcs):
  out = ''
  for cfn in cgs:
    data = subprocess.check_output(['callgrind_annotate', cfn] + srcs)
    out += '%s\n%s\n' % (data, '-' * 80)
  return out

def parse(fn, data, prev):
  source = open(fn).read().split('\n')
  out = prev
  if not out:
    out = [None] * len(source)
    for i in range(len(source)):
      if is_asm(source[i]):
        out[i] = 0

  line = None
  for l in data.split('\n'):
    if l.startswith('-- line'):
      line = int(l.split(' ')[2]) - 1
    elif line != None and '=>' not in l:
      l = l.strip() + ' '
      num = l.split(' ')[0].replace(',', '').replace('.', '0')
      instr = l.split(' ', 1)[1].strip()
      if num != '0' or is_asm(instr):
        if out[line] == None:
          out[line] = 0
        out[line] += int(num)
      line += 1

  return out

def generate(data):
  out = {}
  data = [p.strip() for p in data.split('-' * 80)]
  i = 0
  while i < len(data):
    if 'User-annotated source' in data[i] and i < len(data) - 1:
      fn = data[i].split(':', 1)[1].strip()
      res = data[i + 1]
      if fn not in out:
        out[fn] = None
      if 'No information' in res:
        res = ''
      out[fn] = parse(fn, res, out[fn])
    i += 1
  return out

def output(data):
  out = ''
  for fn,lines in data.iteritems():
    out += 'SF:%s\n' % (os.path.abspath(fn))
    for ln in range(len(lines)):
      if lines[ln] == None:
        continue
      out += 'DA:%d,%s\n' % (ln + 1, lines[ln])
    out += 'end_of_record\n'
  return out

if __name__ == '__main__':
  if len(sys.argv) != 3:
    print '%s <Callgrind Folder> <Build Folder>' % (__file__)
    sys.exit()

  cg_folder = sys.argv[1]
  build_folder = sys.argv[2]

  cgs = [os.path.abspath(os.path.join(cg_folder, f)) for f in os.listdir(cg_folder)]
  srcs = []

  for (cwd, _, files) in os.walk(build_folder):
    for f in files:
      fn = os.path.join(cwd, f)
      if fn.endswith('.S'):
        srcs.append(fn)

  data = merge(cgs, srcs)
  lcov = generate(data)
  print output(lcov)
