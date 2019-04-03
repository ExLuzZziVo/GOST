#region

using System;
using System.Collections.Generic;
using GOST.Interfaces;

#endregion

namespace GOST.Ciphers
{
    internal class XORCipher : IXORCipher
    {
        private readonly SubstitutionCipher substitution;
        private uint n3;
        private uint n4;

        public XORCipher(ISBlocks sBlock)
        {
            substitution = new SubstitutionCipher(sBlock);
        }

        /// <summary>
        ///     Первоначальная установка состояния шифра.
        /// </summary>
        /// <param name="iv">Синхропосылка.</param>
        /// <param name="subKeys">Подключи.</param>
        public void SetIV(byte[] iv, List<uint> subKeys)
        {
            var encodedIV = substitution.EncodeProcess(iv, subKeys);

            n3 = BitConverter.ToUInt32(encodedIV, 0);
            n4 = BitConverter.ToUInt32(encodedIV, 4);
        }

        /// <summary>
        ///     Процесс шифрования открытого текста
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKeys">Коллекция подключей.</param>
        /// <returns>Блок шифротекста.</returns>
        public byte[] EncodeProcess(byte[] data, List<uint> subKeys)
        {
            n3 += 16843009 % 4294967295;
            n4 += 16843012 % 4294967294;

            var n1 = n3;
            var n2 = n4;

            var gamma = new byte[8];
            Array.Copy(BitConverter.GetBytes(n1), 0, gamma, 0, 4);
            Array.Copy(BitConverter.GetBytes(n2), 0, gamma, 4, 4);
            gamma = substitution.EncodeProcess(gamma, subKeys);

            return XOR(gamma, data);
        }

        /// <summary>
        ///     Процесс дешифровки шифротекста.
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKeys">Коллекция подключей.</param>
        /// <returns>Блок открытого текста.</returns>
        public byte[] DecodeProcess(byte[] data, List<uint> subKeys)
        {
            return EncodeProcess(data, subKeys);
        }

        /// <summary>
        ///     Применение XOR между гаммой и блоком данных.
        /// </summary>
        /// <param name="gamma">Гамма.</param>
        /// <param name="data">Блок данных.</param>
        /// <returns>Результат XOR.</returns>
        private byte[] XOR(byte[] gamma, byte[] data)
        {
            var len = data.Length;
            var res = new byte[len];

            for (var i = 0; i != len; i++) res[i] = (byte) (gamma[i] ^ data[i]);

            return res;
        }
    }
}