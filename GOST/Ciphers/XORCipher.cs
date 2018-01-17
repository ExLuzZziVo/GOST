using GOST.Interfaces;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("GOSTTests")]

namespace GOST.Ciphers
{
    internal class XORCipher : IXORCipher
    {
        private uint n3;
        private uint n4;

        private SubstitutionCipher substitution;

        public XORCipher(ISBlocks sBlock)
        {
            substitution = new SubstitutionCipher(sBlock);
        }

        /// <summary>
        /// Первоначальная установка состояния шифра.
        /// </summary>
        /// <param name="synchroSignal">Синхропосылка.</param>
        /// <param name="subKeys">Подключи.</param>
        public void SetIV(byte[] synchroSignal, List<uint> subKeys)
        {
            byte[] encodedSynchroSignal = substitution.EncodeProcess(synchroSignal, subKeys);

            n3 = BitConverter.ToUInt32(encodedSynchroSignal, 0);
            n4 = BitConverter.ToUInt32(encodedSynchroSignal, 4);
        }

        /// <summary>
        /// Процесс шифрования открытого текста
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <returns>Блок шифротекста.</returns>
        public byte[] EncodeProcess(byte[] data, List<uint> subKeys)
        {
            n3 += 16843009 % 4294967295;
            n4 += 16843012 % 4294967294;

            uint n1 = n3;
            uint n2 = n4;

            byte[] gamma = new byte[8];
            Array.Copy(BitConverter.GetBytes(n1), 0, gamma, 0, 4);
            Array.Copy(BitConverter.GetBytes(n2), 0, gamma, 4, 4);
            gamma = substitution.EncodeProcess(gamma, subKeys);

            return XOR(gamma, data);
        }

        /// <summary>
        /// Процесс дешифровки шифротекста.
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <returns>Блок открытого текста.</returns>
        public byte[] DecodeProcess(byte[] data, List<uint> subKeys)
        {
            return EncodeProcess(data, subKeys);
        }

        /// <summary>
        /// Применение XOR между гаммой и блоком данных.
        /// </summary>
        /// <param name="gamma">Гамма.</param>
        /// <param name="data">Блок данных.</param>
        /// <returns>Результат XOR.</returns>
        private byte[] XOR(byte[] gamma, byte[] data)
        {
            int len = data.Length;
            byte[] res = new byte[len];

            for (int i = 0; i != len; i++)
            {
                res[i] = (byte)(gamma[i] ^ data[i]);
            }

            return res;
        }
    }
}
