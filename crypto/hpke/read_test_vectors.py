# Lint as: python3
"""This script translates JSON test vectors to BoringSSL's "FileTest" format.

Usage: python3 read_test_vectors.py TEST_VECTORS_JSON_FILE

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
    postfix = (50 - len(prefix)) * "-"
    return "# {} {} {}\n".format(prefix, label, postfix)

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

  # Load the JSON file into |test_vectors|.
  with open(json_file_in_path) as file_in:
    test_vectors = json.load(file_in, object_pairs_hook=collections.OrderedDict)

  # Select only the test vectors that our HPKE implementation supports.
  test_vectors = filter(lambda t: t["mode"] == HPKE_MODE_BASE, test_vectors)
  test_vectors = filter(lambda t: t["kemID"] == HPKE_DHKEM_X25519_SHA256,
                        test_vectors)

  # Translate each test vector's top-level keys. Drops fields that are either
  # unnecessary to include or are internal to the implementation.
  key_mapping = {
      "nonce": "outerNonce",  # Avoid name collision with inner "nonce" key.
      "mode": None,
      "kemID": None,
      "zz": None,
      "secret": None,
      "key": None,
  }
  test_vectors = map(lambda t: rename_odict_keys(key_mapping, t), test_vectors)

  with open(test_file_out_path, "w") as file_out:
    file_out.write("\n".join(map(flatten_to_str, test_vectors)))


def main(argv):
  if len(argv) != 2:
    print(__doc__)
    sys.exit(1)

  read_test_vectors_and_generate_code(argv[1], "hpke_test_vectors.txt")


if __name__ == "__main__":
  main(sys.argv)
