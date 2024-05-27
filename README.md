# Encrypt and decrypt using Bellaso algo

Normal Bellaso crypto algorithms just uses 26 letters.  This program adds the ten digits, space and four punctuation marks.  Some Bellaso programs spell out the numbers if they encounter a digit in the plaintext file; this becomes cumbersome (not to mention incorrect) with numbers greater than nine.

```
USAGE: BellasoPlus {-e|-d} keyword infile outfile [options]
Options:
 -v  = verbose
 -t  = print table
```

The Bellaso Cipher encoding creates an encoded file which exhibits a nonsensical character distribution.  Code breaking cannot be achieved by analyzing the character distribution of the encoded file.  See BellasoCipher.png.

Longer, more complex keywords result in stronger encryption.

