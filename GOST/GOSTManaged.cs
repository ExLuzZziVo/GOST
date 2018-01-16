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
        /// Сообщение.
        /// </summary>
        private byte[] message;

        /// <summary>
        /// 64 битная синхропосылка.
        /// </summary>
        private byte[] synchroSignal;

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
        /// Проверка синхропосылки.
        /// </summary>
        /// <exception cref="ArgumentException"></exception>
        public byte[] SynchroSignal
        {
            get { return synchroSignal; }
            set
            {
                if (value.Length != 8)
                {
                    throw new ArgumentException("Wrong synchrosignal. Try to use 64 bit synchrosignal.");
                }
                else if (value.Length == 8)
                {
                    synchroSignal = value;
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

        /// <summary>
        /// Шифрование подстановкой.
        /// </summary>
        /// <param name="key">256 битный ключ.</param>
        /// <param name="message">Данные кратные 64 битам.</param>
        /// <param name="sBlockType">Таблица шифрования</param>
        /// <returns>Зашифрованные данные.</returns>
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
        /// Дешифрование подстановкой.
        /// </summary>
        /// <param name="key">256 битный ключ.</param>
        /// <param name="message">Шифроданные кратные 64 битам.</param>
        /// <param name="sBlockType">Таблица шифрования</param>
        /// <returns>Открытые данные.</returns>
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
        /// <param name="key">256 битный ключ.</param>
        /// <param name="synchroSignal">64 битная шифропосылка.</param>
        /// <param name="message">Открытые данные.</param>
        /// <param name="sBlockType">Таблица шифрования</param>
        /// <returns>Зашифрованные данные.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] XOREncode(byte[] key, byte[] synchroSignal, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST)
        {
            Key = key;
            Message = message;
            SynchroSignal = synchroSignal;

            this.sBlockType = sBlockType;
            SetSBlock();

            byte[] encode = XORProcess();
            return encode;
        }

        /// <summary>
        /// Дешифрование гаммированием.
        /// </summary>
        /// <param name="key">256 битный ключ.</param>
        /// <param name="synchroSignal">64 битная шифропосылка.</param>
        /// <param name="message">Шифроданные.</param>
        /// <param name="sBlockType">Таблица шифрования</param>
        /// <returns>Открытые данные.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] XORDecode(byte[] key, byte[] synchroSignal, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST)
        {
            return XOREncode(key, synchroSignal, message, sBlockType); ;
        }

        /// <summary>
        /// Шифрование гаммированием.
        /// </summary>
        /// <param name="flag">Шифрование/Дешифрование</param>
        /// <returns>Результат шифрования.</returns>
        private byte[] XORProcess()
        {
            var cipher = new XORCipher(sBlock);

            GetSubKeys();

            byte[] res = new byte[message.Length];
            int index = 0;

            cipher.SetSynchroSignal(synchroSignal, subKeys);

            foreach (var chunk in ReadByChunk())
            {
                Array.Copy(cipher.EncodeProcess(chunk, subKeys), 0, res, index, chunk.Length);
                index += chunk.Length;
            }
            return res;
        }

        /// <summary>
        /// Шифрование гаммированием с обратной связью
        /// </summary>
        /// <param name="key">256 битный ключ.</param>
        /// <param name="synchroSignal">64 битная шифропосылка.</param>
        /// <param name="message">Открытые данные.</param>
        /// <param name="sBlockType">Таблица шифрования</param>
        /// <returns>Зашифрованные данные.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] ReverseXOREncode(byte[] key, byte[] synchroSignal, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST)
        {
            Key = key;
            Message = message;
            SynchroSignal = synchroSignal;

            this.sBlockType = sBlockType;
            SetSBlock();

            byte[] encode = ReverseXORProcess(true);
            return encode;
        }

        /// <summary>
        /// Дешифрование гаммированием с обратной связью
        /// </summary>
        /// <param name="key">256 битный ключ.</param>
        /// <param name="synchroSignal">64 битная шифропосылка.</param>
        /// <param name="message">Шифроданные.</param>
        /// <param name="sBlockType">Таблица шифрования</param>
        /// <returns>Открытые данные.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] ReverseXORDecode(byte[] key, byte[] synchroSignal, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST)
        {
            Key = key;
            Message = message;
            SynchroSignal = synchroSignal;

            this.sBlockType = sBlockType;
            SetSBlock();

            byte[] encode = ReverseXORProcess(false);
            return encode;
        }

        /// <summary>
        /// Шифрование гаммированием с обратной связью.
        /// </summary>
        /// <param name="flag">Шифрование/Дешифрование.</param>
        /// <returns>Результат шифрования.</returns>
        private byte[] ReverseXORProcess(bool flag)
        {
            var cipher = new ReverseXORCipher(sBlock);

            GetSubKeys();

            byte[] res = new byte[message.Length];
            int index = 0;

            cipher.SetSynchroSignal(synchroSignal);

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
                synchroSignal = null;
                subKeys.Clear();
            }
        }
    }
}