﻿using GOST.Ciphers;
using GOST.Interfaces;
using GOST.SBlocks;
using GOST.Types;
using System;
using System.Collections.Generic;

namespace GOST
{
    /// <summary>
    /// GOST stream cipher.
    /// </summary>
    public class GOSTManaged : IManaged, IDisposable
    {
        /// <summary>
        /// SBlock table.
        /// </summary>
        private ISBlocks sBlock;

        /// <summary>
        /// SBlock type.
        /// </summary>
        private SBlockTypes sBlockType;

        /// <summary>
        /// 256 bit key;
        /// </summary>
        private byte[] key;

        /// <summary>
        /// Message.
        /// </summary>
        private byte[] message;

        /// <summary>
        /// 64 bit IV.
        /// </summary>
        private byte[] iv;

        /// <summary>
        /// Subkeys.
        /// </summary>
        private List<uint> subKeys;

        /// <summary>
        /// IDisposable flag;
        /// </summary>
        private bool released;

        /// <summary>
        /// Check key length.
        /// </summary>
        /// <exception cref="ArgumentException">Key must have 256 bit length.</exception>
        private byte[] Key
        {
            get { return key; }
            set
            {
                if (value.Length != 32)
                {
                    throw new ArgumentException("Wrong key. Try to use 256 bit key.");
                }
                else if (value.Length == 32)
                {
                    key = value;
                }
            }
        }

        /// <summary>
        /// Check message.
        /// </summary>
        /// <exception cref="ArgumentException">Empty message.</exception>
        private byte[] Message
        {
            get { return message; }
            set
            {
                if (value == null || value.Length == 0)
                {
                    throw new ArgumentException("Empty message!");
                }
                else
                {
                    message = value;
                }
            }
        }

        /// <summary>
        /// Check IV.
        /// </summary>
        /// <exception cref="ArgumentException">IV must have 256 bit length.</exception>
        private byte[] IV
        {
            get { return iv; }
            set
            {
                if (value.Length != 8)
                {
                    throw new ArgumentException("Wrong IV. Try to use 64 bit IV.");
                }
                else if (value.Length == 8)
                {
                    iv = value;
                }
            }
        }

        /// <summary>
        /// GOST stream cipher.
        /// </summary>
        public GOSTManaged()
        {
            released = false;
            subKeys = new List<uint>();
        }

        /// <summary>
        /// Set SBlockTable.
        /// </summary>
        /// <exception cref="Exception">Oops...</exception>
        private void SetSBlock()
        {
            switch (sBlockType)
            {
                case SBlockTypes.CryptoProA:
                    sBlock = new CryptoProABlock();
                    break;
                case SBlockTypes.CryptoProB:
                    sBlock = new CryptoProBBlock();
                    break;
                case SBlockTypes.CryptoProC:
                    sBlock = new CryptoProCBlock();
                    break;
                case SBlockTypes.CryptoProD:
                    sBlock = new CryptoProDBlock();
                    break;
                case SBlockTypes.GOST:
                    sBlock = new GOSTBlock();
                    break;
                case SBlockTypes.TC26:
                    sBlock = new TC26Block();
                    break;
                default:
                    sBlock = null;
                    throw new Exception("Something wrong...");
            }
        }

        /// <summary>
        /// Generate subkeys.
        /// </summary>
        private void GetSubKeys()
        {
            byte[] res = new byte[4];
            // Stage 1.
            int j = 0;
            for (int i = 0; i != key.Length; i++)
            {
                res[j] = key[i];

                if (j % 3 == 0 && j != 0)
                {
                    subKeys.Add(BitConverter.ToUInt32(res, 0));
                    j = 0;
                }
                else
                {
                    j++;
                }
            }
            // Stage 2.
            for (int i = 0; i != 16; i++)
            {
                subKeys.Add(subKeys[i]);
            }
            // Stage 3.
            for (int i = 7; i != -1; i--)
            {
                subKeys.Add(subKeys[i]);
            }
        }

        /// <summary>
        /// Substitution encode.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="message">Opened message multiple of 64 bit.</param>
        /// <param name="sBlockType">STable.</param>
        /// <returns>Encoded message.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] SubstitutionEncode(byte[] key, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST)
        {
            Key = key;
            Message = message;
            if (message.Length % 8 != 0)
            {
                throw new ArgumentException("Block must have 64 bit length");
            }
            this.sBlockType = sBlockType;
            SetSBlock();

            byte[] encode = SubstitutionProcess(true);
            return encode;
        }

        /// <summary>
        /// Substitution decode.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="message">Encoded message multiple of 64 bit.</param>
        /// <param name="sBlockType">STable.</param>
        /// <returns>Opened message</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] SubstitutionDecode(byte[] key, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST)
        {
            Key = key;
            Message = message;
            if (message.Length % 8 != 0)
            {
                throw new ArgumentException("Block must have 64 bit length");
            }
            this.sBlockType = sBlockType;
            SetSBlock();

            byte[] decode = SubstitutionProcess(false);
            return decode;
        }

        /// <summary>
        /// Substitution.
        /// </summary>
        /// <param name="flag">Encode/decode.</param>
        /// <returns>Result.</returns>
        private byte[] SubstitutionProcess(bool flag)
        {
            var cipher = new SubstitutionCipher(sBlock);
            GetSubKeys();
            if (!flag)
            {
                subKeys.Reverse();
            }
            byte[] res = new byte[message.Length];
            int index = 0;

            foreach (var chunk in ReadByChunk())
            {
                if (flag)
                {
                    Array.Copy(cipher.EncodeProcess(chunk, subKeys), 0, res, index, 8);
                }
                else
                {
                    Array.Copy(cipher.DecodeProcess(chunk, subKeys), 0, res, index, 8);
                }
                index += 8;
            }
            return res;
        }

        /// <summary>
        /// XOR encode.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="iv">64 bit IV</param>
        /// <param name="message">Opened message.</param>
        /// <param name="sBlockType">STable.</param>
        /// <returns>Encoded message.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] XOREncode(byte[] key, byte[] iv, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST)
        {
            Key = key;
            Message = message;
            IV = iv;

            this.sBlockType = sBlockType;
            SetSBlock();

            byte[] encode = XORProcess();
            return encode;
        }

        /// <summary>
        /// XOR decode.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="iv">64 bit IV</param>
        /// <param name="message">Encoded message.</param>
        /// <param name="sBlockType">STable.</param>
        /// <returns>Opened message.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] XORDecode(byte[] key, byte[] iv, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST)
        {
            return XOREncode(key, iv, message, sBlockType); ;
        }

        /// <summary>
        /// XOR.
        /// </summary>
        /// <returns>Result.</returns>
        private byte[] XORProcess()
        {
            var cipher = new XORCipher(sBlock);

            GetSubKeys();

            byte[] res = new byte[message.Length];
            int index = 0;

            cipher.SetIV(iv, subKeys);

            foreach (var chunk in ReadByChunk())
            {
                Array.Copy(cipher.EncodeProcess(chunk, subKeys), 0, res, index, chunk.Length);
                index += chunk.Length;
            }
            return res;
        }

        /// <summary>
        /// CFB encode.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="iv">64 bit IV</param>
        /// <param name="message">Opened message.</param>
        /// <param name="sBlockType">STable.</param>
        /// <returns>Encoded message.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] CFBEncode(byte[] key, byte[] iv, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST)
        {
            Key = key;
            Message = message;
            IV = iv;

            this.sBlockType = sBlockType;
            SetSBlock();

            byte[] encode = CFBProcess(true);
            return encode;
        }

        /// <summary>
        /// CFB decode.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="iv">64 bit IV</param>
        /// <param name="message">Encoded message.</param>
        /// <param name="sBlockType">STable.</param>
        /// <returns>Opened message.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] CFBDecode(byte[] key, byte[] iv, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST)
        {
            Key = key;
            Message = message;
            IV = iv;

            this.sBlockType = sBlockType;
            SetSBlock();

            byte[] encode = CFBProcess(false);
            return encode;
        }

        /// <summary>
        /// CFB.
        /// </summary>
        /// <param name="flag">Encode/decode.</param>
        /// <returns>Result.</returns>
        private byte[] CFBProcess(bool flag)
        {
            var cipher = new CFBCipher(sBlock);

            GetSubKeys();

            byte[] res = new byte[message.Length];
            int index = 0;

            cipher.SetIV(iv);

            foreach (var chunk in ReadByChunk())
            {
                if (flag)
                {
                    Array.Copy(cipher.EncodeProcess(chunk, subKeys), 0, res, index, chunk.Length);
                }
                else
                {
                    Array.Copy(cipher.DecodeProcess(chunk, subKeys), 0, res, index, chunk.Length);
                }
                index += chunk.Length;
            }
            return res;
        }


        /// <summary>
        /// MAC generator.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="message">Message (not less than 2 blocks).</param>
        /// <param name="sBlockType">SBlock.</param>
        /// <returns>MAC.</returns>
        public byte[] MACGenerator(byte[] key, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST)
        {
            Key = key;
            Message = message;

            this.sBlockType = sBlockType;
            SetSBlock();

            byte[] mac = MACProcess();
            return mac;
        }

        /// <summary>
        /// MAC.
        /// </summary>
        /// <returns>Result.</returns>
        private byte[] MACProcess()
        {
            var generator = new MACGenerator(sBlock);

            GetSubKeys();

            byte[] res = new byte[8];

            foreach (var chunk in ReadByChunk())
            {
                res = generator.Process(chunk, subKeys);
            }
            return res;
        }

        /// <summary>
        /// Read message by chunks.
        /// </summary>
        /// <returns>At least 64 bit block.</returns>
        private IEnumerable<byte[]> ReadByChunk()
        {
            for (int i = 0; i < message.Length; i += 8)
            {
                var min = Math.Min(8, message.Length - i);

                byte[] res = new byte[min];

                Array.Copy(message, i, res, 0, min);

                yield return res;
            }
        }

        /// <summary>
        /// Dispose.
        /// </summary>
        public void Dispose()
        {
            if (!released)
            {
                released = true;

                sBlock = null;
                message = null;
                key = null;
                iv = null;
                subKeys.Clear();
            }
        }
    }
}