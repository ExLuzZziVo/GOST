using GOST.Ciphers;
using GOST.Interfaces;
using GOST.Types;
using System;
using System.Collections.Generic;

namespace GOST
{
    public class GOSTManaged : IManager
    {
        /// <summary>
        /// Шифровальщик.
        /// </summary>
        private ICipher cipher;
        /// <summary>
        /// Тип шифровальщика.
        /// </summary>
        private CipherTypes cipherType;
        /// <summary>
        /// Тип SBlock таблицы.
        /// </summary>
        private SBlockTypes sBlockType;
        /// <summary>
        /// 256 битный ключ.
        /// </summary>
        private byte[] key;
        /// <summary>
        /// 32 блока подключей.
        /// Основа подключей - 8 32ух битных блоков.
        /// 1 - 8 блоки: 8 основных 32 битных блоков от обычного ключа.
        /// 9 - 24 блоки: циклическое повторение блоков 1 - 8 (нумерация от младших к старшим битам).
        /// 25 - 32 блоки : блоки 8 - 1 (именно в таком порядке).
        /// </summary>
        private List<byte[]> subKeys;
        /// <summary>
        /// Сообщение.
        /// </summary>
        private byte[] message;

        /// <summary>
        /// Проверка ключа на величину.
        /// </summary>
        public byte[] Key
        {
            get { return key; }
            set
            {
                if (value.Length > 32)
                {
                    throw new ArgumentException("Key Overflow. Try to use 256 bit key.");
                }
                else if (value.Length == 32)
                {
                    key = value;
                }
                else
                {
                    key = value;
                    for (int i = value.Length; i != 32; i++)
                    {
                        var newKey = new byte[key.Length + 1];
                        key.CopyTo(newKey, 0);
                        newKey[newKey.Length - 1] = 0;
                        key = newKey;
                    }
                }
            }
        }

        /// <summary>
        /// Проверка сообщения на null.
        /// </summary>
        public byte[] Message
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
        /// Конструктор менеджера.
        /// </summary>
        /// <param name="key">256 битный ключ.</param>
        /// <param name="message">Сообщение.</param>
        /// <param name="cipherType">Тип шифрования.</param>
        /// <param name="sBlockType">SBlock таблица.</param>
        public GOSTManaged(byte[] key, byte[] message, CipherTypes cipherType, SBlockTypes sBlockType = SBlockTypes.GOST)
        {
            Key = key;
            Message = message;
            this.cipherType = cipherType;
            this.sBlockType = sBlockType;
        }

        /// <summary>
        /// Шифрование.
        /// </summary>
        /// <returns>Результат шифрования.</returns>
        public byte[] Encode()
        {
            byte[] encode;
            switch (cipherType)
            {
                case CipherTypes.Substitution:
                    encode = SubstitutionEncode();
                    break;
                case CipherTypes.XOR:
                    encode = XOREncode();
                    break;
                case CipherTypes.ReverseXOR:
                    encode = ReverseXOREncode();
                    break;
                case CipherTypes.MAC:
                    encode = MACEncode();
                    break;
                default:
                    encode = null;
                    throw new Exception("Something wrong...");
            }
            return encode;
        }

        /// <summary>
        /// Шифрование подстановкой.
        /// </summary>
        /// <returns>Результат шифрования.</returns>
        private byte[] SubstitutionEncode()
        {
            cipher = new SubstitutionCipher();
            return new byte[] { 1 };
        }

        /// <summary>
        /// Шифрование гаммированием.
        /// </summary>
        /// <returns>Результат шифрования.</returns>
        private byte[] XOREncode()
        {
            cipher = new XORCipher();
            return new byte[] { 1 };
        }

        /// <summary>
        /// Шифрование гаммированием с обратной связью.
        /// </summary>
        /// <returns>Результат шифрования.</returns>
        private byte[] ReverseXOREncode()
        {
            cipher = new ReverseXORCipher();
            return new byte[] { 1 };
        }

        /// <summary>
        /// Шифрование иммитовставкой.
        /// </summary>
        /// <returns>Результат шифрования.</returns>
        private byte[] MACEncode()
        {
            cipher = new MACCipher();
            return new byte[] { 1 };
        }
    }
}