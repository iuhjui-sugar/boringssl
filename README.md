# BoringSSL

BoringSSL is a fork of OpenSSL that is designed to meet Google's needs. Google
has used OpenSSL for many years in various ways and, over time, had built up a
large number of patches that were maintained while tracking upstream OpenSSL.
As Google's product portfolio became more complex, more copies of OpenSSL
sprung up and the effort involved in maintaining all these patches in multiple
places was growing steadily.

There are no guarantees of API or ABI stability with this code: we are not
aiming to replace OpenSSL as an open-source project. We also do not intend for
third parties to depend on BoringSSL. It's open-source, of course, but
BoringSSL is not taking on any implied duty to developers who use this library
as might be expected of an open-source project.

Google products ship their own copies of BoringSSL when they use it and we
update everything as needed when deciding to make API changes. This allows us
to mostly avoid compromises in the name of compatibility. It works for us, but
it may not work for you.

Currently BoringSSL is the SSL library in Chrome/Chromium, Android (but it's
not part of the NDK) and other apps/programs produced by Google.


There are other files in this directory which might be helpful:

  * PORTING.md: how to port OpenSSL-using code to BoringSSL.
  * BUILDING: how to build BoringSSL
  * STYLE: rules and guidelines for coding style.
