#!/usr/bin/env python
# coding=utf-8
# Copyright (c) 2020, Google Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""This script translates JSON test vectors to BoringSSL's "FileTest" format.

Usage: translate_test_vectors.py TEST_VECTORS_JSON_FILE

The TEST_VECTORS_JSON_FILE is expected to come from the HPKE reference
implementation at https://github.com/cisco/go-hpke. The output file is
hardcoded as "hpke_test_vectors.txt".
"""

import collections
import json
import sys

HPKE_MODE_BASE = 0
HPKE_DHKEM_X25519_SHA256 = 0x0020


def flatten_to_str(obj, keypath=None):
  """Flattens |obj| to a FileTest-parseable string."""

  if keypath is None:
    keypath = []

  def build_comment(label):
    prefix = len(keypath) * "----"
    suffix = (50 - len(prefix)) * "-"
    return "# {} {} {}\n".format(prefix, label, suffix)

  pieces = []
  if isinstance(obj, dict) or isinstance(obj, collections.OrderedDict):
    for key in obj:
      pieces.append(flatten_to_str(obj[key], keypath=keypath + [key]))
  elif isinstance(obj, list):
    for i, elem in enumerate(obj):
      label = "{}[{}]".format(keypath[-1], i)
      pieces.append(build_comment(label))
      pieces.append(flatten_to_str(elem, keypath=keypath + [label]))
  else:
    if keypath:
      pieces.append("{} = {}\n".format(keypath[-1], str(obj)))
  return "".join(pieces)


def rename_odict_keys(subst, odict):
  """Copies |odict| with new key names determined by |subst|.

  Args:
    subst: a dict that maps current keys to their new names.
    odict: an ordered dict whose keys will be renamed.

  Returns:
    A copy of |odict| with new key names. Order of key-value pairs is preserved.
    Any pairs where subst[key] is None are dropped.
  """
  return collections.OrderedDict([(subst.get(k, k), odict[k])
                                  for k in odict
                                  if k not in subst or subst[k] is not None])


def read_test_vectors_and_generate_code(json_file_in_path, test_file_out_path):
  """Reads the file at |json_file_in_path| and writes to |test_file_out_path|."""

  # Load the JSON file into |test_vecs| as an ordered dict.
  with open(json_file_in_path) as file_in:
    test_vecs = json.load(file_in, object_pairs_hook=collections.OrderedDict)

  # Select only the test vectors that our HPKE implementation supports.
  test_vecs = [t for t in test_vecs if t["mode"] == HPKE_MODE_BASE]
  test_vecs = [t for t in test_vecs if t["kemID"] == HPKE_DHKEM_X25519_SHA256]

  # Translate each test vector's top-level keys. Drops fields that are either
  # unnecessary to include or are internal to the implementation.
  key_mapping = {
      # Avoid name collision between top-level test vector's nonce and
      # individual encryptions' nonces.
      "nonce": "outerNonce",
      # Unnecessary to include attributes that will never vary due to filtering.
      "mode": None,
      "kemID": None,
      # These values are internal to the implementation. It may be useful to
      # unmask these when debugging.
      "zz": None,
      "secret": None,
      "key": None,
      # We are not implementing DeriveKeyPair, so we don't need these seeds.
      "seedR": None,
      "seedE": None,
      # For X25519, "enc" is equivalent to "pkEm".
      "enc": None,
  }
  test_vecs = map(lambda t: rename_odict_keys(key_mapping, t), test_vecs)
  test_vecs_flattened = "\n".join(map(flatten_to_str, test_vecs))

  with open(test_file_out_path, "w") as file_out:
    file_out.write(test_vecs_flattened)


def main(argv):
  if len(argv) != 2:
    print(__doc__)
    sys.exit(1)

  read_test_vectors_and_generate_code(argv[1], "hpke_test_vectors.txt")


if __name__ == "__main__":
  main(sys.argv)
