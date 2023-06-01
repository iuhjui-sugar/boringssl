/* Copyright (c) 2023, Google Inc.
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
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/// Compares the slices `a` and `b`. It takes an amount of time dependent on the lengths, but
/// independent of the contents of the slices `a` and `b`.
pub fn memcmp(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // Safety:
    // - The lengths of a and b are checked above.
    let result =
        unsafe { bssl_sys::CRYPTO_memcmp(a.as_ptr() as *const _, b.as_ptr() as *const _, a.len()) };
    result == 0
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_different_length() {
        assert!(!memcmp(&[0, 1, 2], &[0]))
    }

    #[test]
    fn test_same_length_different_content() {
        assert!(!memcmp(&[0, 1, 2], &[1, 2, 3]))
    }

    #[test]
    fn test_same_content() {
        assert!(memcmp(&[0, 1, 2], &[0, 1, 2]))
    }
}