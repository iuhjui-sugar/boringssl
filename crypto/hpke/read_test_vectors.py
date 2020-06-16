# Lint as: python3

import json
import pprint
import string
import sys


def generate_cpp_code_hex(vec, json_key, cpp_var):
  return "ParseHex(\"{}\") /* {} */,\n".format(vec[json_key], cpp_var)


def generate_cpp_code(vec):
  s = "const HpkeTestVector kTestVectorBaseSetup{"

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


def read_test_vectors(filepath):
  with open(filepath) as f:
    test_vectors = json.load(f)

  # Mode = mode_base
  test_vectors = filter(lambda v: v["mode"] == 0, test_vectors)
  # KEM = DHKEM(Curve25519, HKDF-SHA256).
  test_vectors = filter(lambda v: v["kemID"] == 0x0020, test_vectors)
  # KDF = HKDF-SHA256
  test_vectors = filter(lambda v: v["kdfID"] == 0x0001, test_vectors)
  # AEAD = AES-GCM-128
  test_vectors = filter(lambda v: v["aeadID"] == 0x0001, test_vectors)
  test_vectors = list(test_vectors)

  #print("Filtered down to {} results.".format(len(test_vectors)))

  for vec in test_vectors:
    #pprint.pprint(vec)
    #print("------------")
    print(generate_cpp_code(vec))


def main(argv):
  if len(argv) != 2:
    raise Exception("Usage: {} TEST_VECTORS_JSON_FILE".format(argv[0]))

  read_test_vectors(argv[1])


if __name__ == "__main__":
  main(sys.argv)
