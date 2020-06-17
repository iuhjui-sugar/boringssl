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

def read_test_vectors_and_generate_code(json_file_in, cc_file_out):
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

  cc_vecs = list(map(generate_cpp_code, test_vectors))
  cc_list_of_vecs = '{' + ','.join(cc_vecs) + '}'
  generated_decl = "const std::vector<HpkeTestVector> kTestVectorBaseSetup {};".format(cc_list_of_vecs)

  with open(cc_file_out, 'w') as file_out:
    file_out.write(generated_decl)

def main(argv):
  if len(argv) != 2:
    raise Exception("Usage: {} TEST_VECTORS_JSON_FILE".format(argv[0]))

  read_test_vectors_and_generate_code(argv[1], 'generated_test_vectors.cc')


if __name__ == "__main__":
  main(sys.argv)
