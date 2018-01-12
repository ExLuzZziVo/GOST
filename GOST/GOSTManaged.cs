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
    public class GOSTManaged : IManaged, IDisposable
    {
        /// <summary>
        /// SBlock таблица.
        /// </summary>
        private ISBlocks sBlock;

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
        /// Флаг для IDisposable.
        /// </summary>
        private bool released;

        /// <summary>
        /// Сообщение.
        /// </summary>
        private byte[] message;

        /// <summary>
        /// Проверка ключа на величину.
        /// </summary>
        /// <exception cref="ArgumentException">Ключ должен иметь длину в 256 бит.</exception>
        public byte[] Key
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
        /// Проверка сообщения на null.
        /// </summary>
        /// <exception cref="ArgumentException">Пустое сообщение для шифрования.</exception>
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
        /// Конструктор.
        /// </summary>
        public GOSTManaged()
        {
            released = false;
            subKeys = new List<uint>();
        }

        /// <summary>
        /// Установка выбранного SBlockTable.
        /// </summary>
        /// <exception cref="Exception">Неизвестное исключение. Обратитесь к разработчику.</exception>
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
            byte[] res = new byte[4];
            // Первая стадия.
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
            // Вторая стадия.
            for (int i = 0; i != 16; i++)
            {
                subKeys.Add(subKeys[i]);
            }
            // Третья стадия.
            for (int i = 7; i != -1; i--)
            {
                subKeys.Add(subKeys[i]);
            }
        }

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

            var cipher = new SubstitutionCipher(sBlock);

            byte[] encode = SubstitutionProcess(true);
            return encode;
        }

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

            var cipher = new SubstitutionCipher(sBlock);

            byte[] decode = SubstitutionProcess(false);
            return decode;
        }

        /// <summary>
        /// Шифрование подстановкой.
        /// </summary>
        /// <param name="flag">Шифрование/Дешифрование</param>
        /// <returns>Результат шифрования.</returns>
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
        /// Шифрование гаммированием.
        /// </summary>
        /// <param name="flag">Шифрование/Дешифрование</param>
        /// <returns>Результат шифрования.</returns>
        private byte[] XORProcess(bool flag)
        {
            var cipher = new XORCipher(sBlock);
            return new byte[] { 1 };
        }

        /// <summary>
        /// Шифрование гаммированием с обратной связью.
        /// </summary>
        /// <returns>Результат шифрования.</returns>
        private byte[] ReverseXORProcess(bool flag)
        {
            var cipher = new ReverseXORCipher();
            return new byte[] { 1 };
        }

        /// <summary>
        /// Шифрование иммитовставкой.
        /// </summary>
        /// <param name="flag">Шифрование/Дешифрование</param>
        /// <returns>Результат шифрования.</returns>
        private byte[] MACProcess(bool flag)
        {
            var cipher = new MACCipher();
            return new byte[] { 1 };
        }

        /// <summary>
        /// Чтение сообщения по блокам.
        /// </summary>
        /// <returns>64-х битный блок.</returns>
        /// <exception cref="ArgumentException">Сообщение должно быть кратно 64 битам.</exception>
        // TODO: Возможно этот метод надо будет переделать или убрать в шифр подстановки, только для него работает это ограничение.
        private IEnumerable<byte[]> ReadByChunk()
        {
            for (int i = 0; i < message.Length; i += 8)
            {
                byte[] res = new byte[8];

                try
                {
                    Array.Copy(message, i, res, 0, 8);
                }
                catch (Exception)
                {
                    throw new ArgumentException("Block must have 64 bit length");
                }

                yield return res;
            }
        }

        /// <summary>
        /// Освобождение ресурсов.
        /// </summary>
        public void Dispose()
        {
            if (!released)
            {
                released = true;

                sBlock = null;
                message = null;
                key = null;
                subKeys.Clear();
            }
        }
    }
}