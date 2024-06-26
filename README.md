# Encrypt and decrypt using Bellaso Cipher Algorithm

Normal Bellaso cipher algorithms just uses 26 letters.  This program adds the ten digits, space and four punctuation marks.  Some Bellaso programs spell out the numbers if they encounter a digit in the plaintext file; this becomes cumbersome (not to mention incorrect) with numbers greater than nine.

```
USAGE: BellasoPlus {-e|-d} keyword infile outfile [options]
Options:
 -v  = verbose
 -t  = print table
```

The Bellaso Cipher creates an encrypted file which exhibits a nonsensical character distribution.  Code breaking cannot be achieved by analyzing the character distribution of the encrypted file.  See BellasoCipher.png.

Longer, more complex keywords result in stronger encryption.

Here is a <a href='http://bellaso.silverhammersoftware.com/'>Bellaso Website</a> where you can encrypt, email and decrypt messages.  

