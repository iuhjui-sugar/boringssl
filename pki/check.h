// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PKI_CHECK_H_
#define PKI_CHECK_H_

#include <cassert>

// This header defines the CHECK, DCHECK, macros, inherited from chrome.


// In chrome DCHECK is used like assert() but often erroneously. to be
// safe we make DCHECK the same as CHECK, and if we truly wish to have
// this be an assert, we convert to assert().
#define DCHECK CHECK

// CHECK aborts if a condition is not true.

#define CHECK(A) \
  do {           \
    if (!(A))    \
      abort();   \
  } while (0);

#define DCHECK_EQ CHECK_EQ
#define DCHECK_NE CHECK_NE
#define DCHECK_LE CHECK_LE
#define DCHECK_LT CHECK_LT
#define DCHECK_GE CHECK_GE
#define DCHECK_GT CHECK_GT

#define CHECK_EQ(val1, val2) CHECK((val1) == (val2))
#define CHECK_NE(val1, val2) CHECK((val1) != (val2))
#define CHECK_LE(val1, val2) CHECK((val1) <= (val2))
#define CHECK_LT(val1, val2) CHECK((val1) < (val2))
#define CHECK_GE(val1, val2) CHECK((val1) >= (val2))
#define CHECK_GT(val1, val2) CHECK((val1) > (val2))

#endif  // PKI_CHECK_H_
