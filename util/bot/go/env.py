#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Modified from go/env.py in Chromium infrastructure's repository to patch out
# everything but the core toolchain.
#
# https://chromium.googlesource.com/infra/infra/

"""Used to wrap a command:

$ ./env.py go version
"""

assert __name__ == '__main__'

import os
import subprocess
import sys

# /path/to/util/bot
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def get_go_environ(goroot):
  env = os.environ.copy()
  env['GOROOT'] = goroot
  gobin = os.path.join(goroot, 'bin')
  path = env['PATH'].split(os.pathsep)
  if gobin not in path:
    env['PATH'] = os.pathsep.join([gobin] + path)
  return env

# TODO(davidben): Now that we use CIPD to fetch Go, this script does not do
# much. Switch to setting up GOROOT and PATH in the recipe?
env = get_go_environ(os.path.join(ROOT, 'golang'))
sys.exit(subprocess.call(sys.argv[1:], env=env))
