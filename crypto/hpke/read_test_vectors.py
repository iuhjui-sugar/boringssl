# Lint as: python3

import json
import pprint
import string
import sys


def flatten_to_str(obj, keypath=[]):
  def build_comment(label):
    prefix = len(keypath) * "----"
    postfix = (50 - len(prefix)) * "-"
    return "# {} {} {}\n".format(prefix, label, postfix)

  s = ""
  if type(obj) is dict:
    for key in obj:
      s += flatten_to_str(obj[key], keypath=keypath + [key])
  elif type(obj) is list:
    for i, elem in enumerate(obj):
      label = "{}[{}]".format(keypath[-1], i)
      s += build_comment(label)
      s += flatten_to_str(elem, keypath=keypath + [label])
  else:
    if keypath:
      s += "{} = {}\n".format(keypath[-1], str(obj))

  return s


def read_test_vectors_and_generate_code(json_file_in_path, test_file_out_path):
  """Reads the file at |json_file_in_path| and writes to |test_file_out_path|."""
  with open(json_file_in_path) as file_in:
    test_vectors = json.load(file_in)

  # Mode = mode_base
  test_vectors = filter(lambda v: v["mode"] == 0, test_vectors)
  # KEM = DHKEM(Curve25519, HKDF-SHA256).
  test_vectors = filter(lambda v: v["kemID"] == 0x0020, test_vectors)
  # AEAD = in [AES-GCM-128, AES-GCM-256, ChaCha20Poly1305]
  test_vectors = filter(lambda v: v["aeadID"] in [0x0001, 0x0002, 0x0003], test_vectors)
  test_vectors = list(test_vectors)

  # Each test vector contains a list of encryptions (inputs and outputs). To
  # express this in the BoringSSL "FileTest" format, we must flatten this
  # structure.

  with open(test_file_out_path, "w") as file_out:
    for t in test_vectors:
      # Avoid a name collision between the test vector's nonce and each
      # encryption's nonce.
      t["outerNonce"] = t.pop("nonce")

       # Drop fields that are either unnecessary to include or are internal to
       # the implementation.
      kDroppedAttributes = [ "mode", "kemID", "zz", "secret", "key" ]
      for attr in kDroppedAttributes:
        t.pop(attr)

      file_out.write(flatten_to_str(t))
      file_out.write('\n')

def main(argv):
  if len(argv) != 2:
    raise Exception("Usage: {} TEST_VECTORS_JSON_FILE".format(argv[0]))

  read_test_vectors_and_generate_code(argv[1], "hpke_test_vectors.txt")


if __name__ == "__main__":
  main(sys.argv)
