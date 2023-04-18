# Web PKI Certificate path building and verification library

This directory and library should be considered experimental
and should not be depended upon not to change without notice.

It contains an extracted and modified copy of chrome's certificate
verifier.

It is intended to be synchronized from a checkout of chrome's
head with the IMPORT script run in this directory. 

Current status:

This builds and passes most of the tests with a few exceptions:

- Some of the Path Builder tests depending on chrome testing classes
  and SavedUserData are disabled.

- PathServics is kind of hacked in. and looks for a define to pull
  files from the source directory

- This contains a copy of der as bssl:der - a consideration for
  re-integrating with chromium. the encode_values part of der
  does not include the base::time or absl::time based stuff
  as they are not used within the library, this should probably
  be split out for chrome.


