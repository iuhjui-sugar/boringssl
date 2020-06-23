# Lint as: python3

import json
import pprint
import string
import sys


def generate_cpp_code_hex(vec, json_key, cpp_var):
  return "ParseHex(\"{}\") /* {} */,\n".format(vec[json_key], cpp_var)


def generate_cpp_code(vec):
  s = "{"

  for json_key, cpp_var in [("mode", "mode"), ("kemID", "kem_id"),
                            ("kdfID", "kdf_id"), ("aeadID", "aead_id")]:
    s += "{} /* {} */,\n".format(vec[json_key], cpp_var)

  for json_key, cpp_var in [
      #      ("context", "context"),
      ("key_schedule_context", "context"),
      ("enc", "enc"),
      ("exporterSecret", "exporter_secret"),
      ("info", "info"),
      ("key", "key"),
      ("nonce", "nonce"),
      #      ("pkE", "public_key_e"),
      ("pkEm", "public_key_e"),
      #      ("pkR", "public_key_r"),
      ("pkRm", "public_key_r"),
      ("secret", "secret"),
      #      ("skE", "secret_key_e"),
      ("skEm", "secret_key_e"),
      #      ("skR", "secret_key_r"),
      ("skRm", "secret_key_r"),
      ("zz", "zz"),
  ]:
    s += generate_cpp_code_hex(vec, json_key, cpp_var)

  # Begin std::vector<Encryption>
  s += "{"

  for encryption in vec["encryptions"]:
    s += "HpkeTestVector::Encryption{"
    for json_key, cpp_var in [("aad", "aad"), ("ciphertext", "ciphertext"),
                              ("nonce", "nonce"), ("plaintext", "plaintext")]:
      s += "  " + generate_cpp_code_hex(encryption, json_key, cpp_var)
    s += "},"

  # End std::vector<Encryption>
  s += "}"

  s += "}"
  return s


def flatten_to_str(obj, keypath=[]):
  s = ""

  if type(obj) is dict:
    for key in obj:
      s += flatten_to_str(obj[key], keypath=keypath + [key])
  elif type(obj) is list:
    for elem in obj:
      s += flatten_to_str(elem)
  else:
    if keypath:
      s += "{}={}\n".format(keypath[-1], str(obj))
  return s


def read_test_vectors_and_generate_code(json_file_in):
  with open(json_file_in) as file_in:
    test_vectors = json.load(file_in)

  # Mode = mode_base
  test_vectors = filter(lambda v: v["mode"] == 0, test_vectors)
  # KEM = DHKEM(Curve25519, HKDF-SHA256).
  test_vectors = filter(lambda v: v["kemID"] == 0x0020, test_vectors)
  # KDF = HKDF-SHA256
  test_vectors = filter(lambda v: v["kdfID"] == 0x0001, test_vectors)
  # AEAD = AES-GCM-128 or ChaCha20Poly1305
  test_vectors = filter(lambda v: v["aeadID"] in [0x0001, 0x0003], test_vectors)
  test_vectors = list(test_vectors)

  #print("Filtered down to {} results.".format(len(test_vectors)))

  # Each test vector contains a list of encryptions (inputs and outputs). To
  # express this in the BoringSSL "FileTest" format, we must flatten this
  # structure.

  cc_vecs = list(map(generate_cpp_code, test_vectors))
  cc_list_of_vecs = "{" + ",".join(cc_vecs) + "}"
  generated_decl = "const std::vector<HpkeTestVector> kTestVectors{};".format(
      cc_list_of_vecs)

  # with open("generated_test_vectors.cc, "w") as file_out:
  #   file_out.write(generated_decl)

  with open("hpke_test_vectors.txt", "w") as file_out:
    for t in test_vectors:
      file_out.write("[test]\n")

      # Avoid a name collision between the test vector's nonce and each encryption's nonce.
      t["outer_nonce"] = t.pop("nonce")
      file_out.write(flatten_to_str(t))
      file_out.write("\n")


def main(argv):
  if len(argv) != 2:
    raise Exception("Usage: {} TEST_VECTORS_JSON_FILE".format(argv[0]))

  read_test_vectors_and_generate_code(argv[1])


if __name__ == "__main__":
  main(sys.argv)
