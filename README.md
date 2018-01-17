# GOST
GOST 28147-89 cipher. Шифр ГОСТ 28147-89.

# What is it?
GOST 28147-89 (Magma) - is a Russian government standard symmetric key block cipher.
GOST has a 64-bit block size and a key length of 256 bits.

# Usage
XOR encoding/decoding:
```cs
byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
byte[] iv = Encoding.Default.GetBytes("12345678");
byte[] message = Encoding.Default.GetBytes("12345678876543");

using (var gost = new GOSTManaged())
{
  byte[] encoded = gost.XOREncode(key, iv, message);
  byte[] decoded = gost.XORDecode(key, iv, encoded);
}
```

Optionally, you can change STables (6 tables):
```cs
gost.XOREncode(key, iv, message, SBlockTypes.TS26);
gost.SubstitutionEncode(key, message, SBlockTypes.GOST);
```
By default set GOST table.

All modes:
* Substitution cipher (only 64 bit blocks).
* XOR cipher.
* CFB cipher (XOR with feedback mode).
* MAC generator (for check authenticity of message).

Warning: substitution cipher supports only 64 bit blocks. MAC is not cipher.
