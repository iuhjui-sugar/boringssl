
static void print_point(EC_GROUP *group, EC_RAW_POINT pt) {
  EC_POINT *tmp = EC_POINT_new(group);
  tmp->raw = pt;
  CBB tmp_cbb;
  CBB_init(&tmp_cbb, 0);
  EC_POINT_point2cbb(&tmp_cbb, group, tmp, POINT_CONVERSION_UNCOMPRESSED, NULL);
  uint8_t *buf;
  size_t len;
  CBB_finish(&tmp_cbb, &buf, &len);
  for(size_t i = 0; i < len; i++) { printf("%02x", buf[i]); } printf("\n");
}


    printf("Token #%zu/%zu: %d\n", ++i, sk_TRUST_TOKEN_num(tokens),
           token->data[0] << 8 | token->data[1]);
    if (srr != NULL) {
      printf("SRR: ");
      for(size_t j = 0; j < srr_len; j++) { printf("%02x", srr[j]); }
      printf("\n");
    }
    OPENSSL_free(srr);
    if (sig != NULL) {
      printf("SIG: ");
      for(size_t j = 0; j < sig_len; j++) { printf("%02x", sig[j]); }
      printf("\n");
    }
    OPENSSL_free(sig);
    printf("Result: %d\n", result);
