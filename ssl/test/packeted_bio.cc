/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "packeted_bio.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/mem.h>


namespace {

extern const BIO_METHOD g_packeted_bio_method;

const uint8_t kOpcodePacket = 'P';
const uint8_t kOpcodeTimeout = 'T';
const uint8_t kOpcodeTimeoutAck = 't';

struct PacketedBio {
  explicit PacketedBio(bool advance_clock_arg)
      : advance_clock(advance_clock_arg) {
    memset(&timeout, 0, sizeof(timeout));
    memset(&clock, 0, sizeof(clock));
    memset(&read_deadline, 0, sizeof(read_deadline));
  }

  bool HasTimeout() const {
    return timeout.tv_sec != 0 || timeout.tv_usec != 0;
  }

  bool CanRead() const {
    if (read_deadline.tv_sec == 0 && read_deadline.tv_usec == 0) {
      return true;
    }

    if (clock.tv_sec == read_deadline.tv_sec) {
      return clock.tv_usec < read_deadline.tv_usec;
    }
    return clock.tv_sec < read_deadline.tv_sec;
  }

  timeval timeout;
  timeval clock;
  timeval read_deadline;
  bool advance_clock;
};

PacketedBio *GetData(BIO *bio) {
  if (bio->method != &g_packeted_bio_method) {
    return NULL;
  }
  return (PacketedBio *)bio->ptr;
}

const PacketedBio *GetData(const BIO *bio) {
  return GetData(const_cast<BIO*>(bio));
}

// ReadAll reads |len| bytes from |bio| into |out|. It returns 1 on success and
// 0 or -1 on error.
static int ReadAll(BIO *bio, uint8_t *out, size_t len) {
  while (len > 0) {
    int chunk_len = INT_MAX;
    if (len <= INT_MAX) {
      chunk_len = (int)len;
    }
    int ret = BIO_read(bio, out, chunk_len);
    if (ret <= 0) {
      return ret;
    }
    out += ret;
    len -= ret;
  }
  return 1;
}

static int PacketedWrite(BIO *bio, const char *in, int inl) {
  if (bio->next_bio == NULL) {
    return 0;
  }

  BIO_clear_retry_flags(bio);

  // Write the header.
  uint8_t header[5];
  header[0] = kOpcodePacket;
  header[1] = (inl >> 24) & 0xff;
  header[2] = (inl >> 16) & 0xff;
  header[3] = (inl >> 8) & 0xff;
  header[4] = inl & 0xff;
  int ret = BIO_write(bio->next_bio, header, sizeof(header));
  if (ret <= 0) {
    BIO_copy_next_retry(bio);
    return ret;
  }

  // Write the buffer.
  ret = BIO_write(bio->next_bio, in, inl);
  if (ret < 0 || (inl > 0 && ret == 0)) {
    BIO_copy_next_retry(bio);
    return ret;
  }
  assert(ret == inl);
  return ret;
}

static int PacketedRead(BIO *bio, char *out, int outl) {
  PacketedBio *data = GetData(bio);
  if (bio->next_bio == NULL) {
    return 0;
  }

  BIO_clear_retry_flags(bio);

  for (;;) {
    // Check if the read deadline has passed.
    if (!data->CanRead()) {
      BIO_set_retry_read(bio);
      return -1;
    }

    // Read the opcode.
    uint8_t opcode;
    int ret = ReadAll(bio->next_bio, &opcode, sizeof(opcode));
    if (ret <= 0) {
      BIO_copy_next_retry(bio);
      return ret;
    }

    if (opcode == kOpcodeTimeout) {
      // The caller is required to advance any pending timeouts before
      // continuing.
      if (data->HasTimeout()) {
        fprintf(stderr, "Unprocessed timeout!\n");
        return -1;
      }

      // Process the timeout.
      uint8_t buf[8];
      ret = ReadAll(bio->next_bio, buf, sizeof(buf));
      if (ret <= 0) {
        BIO_copy_next_retry(bio);
        return ret;
      }
      uint64_t timeout = (static_cast<uint64_t>(buf[0]) << 56) |
          (static_cast<uint64_t>(buf[1]) << 48) |
          (static_cast<uint64_t>(buf[2]) << 40) |
          (static_cast<uint64_t>(buf[3]) << 32) |
          (static_cast<uint64_t>(buf[4]) << 24) |
          (static_cast<uint64_t>(buf[5]) << 16) |
          (static_cast<uint64_t>(buf[6]) << 8) |
          static_cast<uint64_t>(buf[7]);
      timeout /= 1000;  // Convert nanoseconds to microseconds.

      data->timeout.tv_usec = timeout % 1000000;
      data->timeout.tv_sec = timeout / 1000000;

      // Send an ACK to the peer.
      ret = BIO_write(bio->next_bio, &kOpcodeTimeoutAck, 1);
      if (ret <= 0) {
        return ret;
      }
      assert(ret == 1);

      if (!data->advance_clock) {
        // Signal to the caller to retry the read, after advancing the clock.
        BIO_set_retry_read(bio);
        return -1;
      }

      PacketedBioAdvanceClock(bio);
      continue;
    }

    if (opcode != kOpcodePacket) {
      fprintf(stderr, "Unknown opcode, %u\n", opcode);
      return -1;
    }

    // Read the length prefix.
    uint8_t len_bytes[4];
    ret = ReadAll(bio->next_bio, len_bytes, sizeof(len_bytes));
    if (ret <= 0) {
      BIO_copy_next_retry(bio);
      return ret;
    }

    uint32_t len = (len_bytes[0] << 24) | (len_bytes[1] << 16) |
        (len_bytes[2] << 8) | len_bytes[3];
    uint8_t *buf = (uint8_t *)OPENSSL_malloc(len);
    if (buf == NULL) {
      return -1;
    }
    ret = ReadAll(bio->next_bio, buf, len);
    if (ret <= 0) {
      fprintf(stderr, "Packeted BIO was truncated\n");
      return -1;
    }

    if (outl > (int)len) {
      outl = len;
    }
    memcpy(out, buf, outl);
    OPENSSL_free(buf);
    return outl;
  }
}

static long PacketedCtrl(BIO *bio, int cmd, long num, void *ptr) {
  if (cmd == BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT) {
    memcpy(&GetData(bio)->read_deadline, ptr, sizeof(timeval));
    return 1;
  }

  if (bio->next_bio == NULL) {
    return 0;
  }
  BIO_clear_retry_flags(bio);
  int ret = BIO_ctrl(bio->next_bio, cmd, num, ptr);
  BIO_copy_next_retry(bio);
  return ret;
}

static int PacketedNew(BIO *bio) {
  bio->init = 1;
  return 1;
}

static int PacketedFree(BIO *bio) {
  if (bio == NULL) {
    return 0;
  }

  delete GetData(bio);
  bio->init = 0;
  return 1;
}

static long PacketedCallbackCtrl(BIO *bio, int cmd, bio_info_cb fp) {
  if (bio->next_bio == NULL) {
    return 0;
  }
  return BIO_callback_ctrl(bio->next_bio, cmd, fp);
}

const BIO_METHOD g_packeted_bio_method = {
  BIO_TYPE_FILTER,
  "packeted bio",
  PacketedWrite,
  PacketedRead,
  NULL /* puts */,
  NULL /* gets */,
  PacketedCtrl,
  PacketedNew,
  PacketedFree,
  PacketedCallbackCtrl,
};

}  // namespace

bssl::unique_ptr<BIO> PacketedBioCreate(bool advance_clock) {
  bssl::unique_ptr<BIO> bio(BIO_new(&g_packeted_bio_method));
  if (!bio) {
    return nullptr;
  }
  bio->ptr = new PacketedBio(advance_clock);
  return bio;
}

timeval PacketedBioGetClock(const BIO *bio) {
  return GetData(bio)->clock;
}

bool PacketedBioAdvanceClock(BIO *bio) {
  PacketedBio *data = GetData(bio);
  if (data == nullptr) {
    return false;
  }

  if (!data->HasTimeout()) {
    return false;
  }

  data->clock.tv_usec += data->timeout.tv_usec;
  data->clock.tv_sec += data->clock.tv_usec / 1000000;
  data->clock.tv_usec %= 1000000;
  data->clock.tv_sec += data->timeout.tv_sec;
  memset(&data->timeout, 0, sizeof(data->timeout));
  return true;
}
