using GOST.Ciphers;
using GOST.Interfaces;
using GOST.SBlocks;
using GOST.Types;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace GOST
{
    public class GOSTManaged : IManager
    {
        /// <summary>
        /// Шифровальщик.
        /// </summary>
        private ICipher cipher;
        /// <summary>
        /// SBlock таблица.
        /// </summary>
        private ISBlocks sBlock;
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
        private List<uint> subKeys;
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
                if (value.Length != 32)
                {
                    throw new ArgumentException("Key Overflow. Try to use 256 bit key.");
                }
                else if (value.Length == 32)
                {
                    key = value;
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
            subKeys = new List<uint>();
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
        /// Установка выбранного SBlockTable.
        /// </summary>
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
        /// Получение коллекции подключей.
        /// </summary>
        private void GetSubKeys()
        {
            byte[] res = new byte[8];
            // Первая стадия.
            for (int i = 0; i != key.Length; i++)
            {
                res[i] = key[i];
                if (i%4 == 0)
                {
                    subKeys.Add(BitConverter.ToUInt32(res, 0));
                }
            }
            // Вторая стадия.
            // TODO: Выспишься - проверь что ты написал за бред тут.
            for (int i = 0; i != 15; i++)
            {
                subKeys.Add(subKeys[i]);
            }
            // Третья стадия.
            for (int i = 7; i != 0; i--)
            {
                subKeys.Add(subKeys[i]);
            }           
        }

        /// <summary>
        /// Шифрование подстановкой.
        /// </summary>
        /// <returns>Результат шифрования.</returns>
        private byte[] SubstitutionEncode()
        {
            cipher = new SubstitutionCipher(sBlock);
            GetSubKeys();
            byte[] res = new byte[message.Length];
            foreach (var chunk in ReadByChunk())
            {
                // TODO: Тестируй это.
                res.Concat(cipher.EncodeProcess(chunk, subKeys));
            }
            return res;
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

        /// <summary>
        /// Чтение сообщения по блокам.
        /// </summary>
        /// <returns>64-х битный блок.</returns>
        private IEnumerable<byte[]> ReadByChunk()
        {
            for (int i = 0; i < message.Length; i += 64)
            {
                byte[] res = new byte[64];

                try
                {
                    Array.Copy(message, res, 64);
                }
                catch (Exception)
                {
                    throw new ArgumentException("Block must have 64 bit length");
                }

                yield return res;
            }
                
        }
    }
}