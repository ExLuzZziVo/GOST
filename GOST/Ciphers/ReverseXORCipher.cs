using GOST.Interfaces;
using GOST.Types;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GOST.Ciphers
{
    internal class ReverseXORCipher : IReverseXORCipher
    {
        private uint n1;
        private uint n2;

        private SubstitutionCipher substitution;

        public ReverseXORCipher(ISBlocks sBlock)
        {
            substitution = new SubstitutionCipher(sBlock);
        }

        /// <summary>
        /// Первоначальная установка состояния шифра.
        /// </summary>
        /// <param name="synchroSignal">Синхропосылка.</param>
        public void SetSynchroSignal(byte[] synchroSignal)
        {
            n1 = BitConverter.ToUInt32(synchroSignal, 0);
            n2 = BitConverter.ToUInt32(synchroSignal, 4);
        }

        /// <summary>
        /// Процесс шифрования открытого текста
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <returns>Блок шифротекста.</returns>
        public byte[] EncodeProcess(byte[] data, List<uint> subKeys)
        {
            byte[] gamma = new byte[8];
            Array.Copy(BitConverter.GetBytes(n1), 0, gamma, 0, 4);
            Array.Copy(BitConverter.GetBytes(n2), 0, gamma, 4, 4);
            gamma = substitution.EncodeProcess(gamma, subKeys);

            byte[] res = XOR(gamma, data);

            if (res.Length == 8)
            {
                n1 = BitConverter.ToUInt32(res, 0);
                n2 = BitConverter.ToUInt32(res, 4);
            }

            return res;
        }

        /// <summary>
        /// Процесс дешифровки шифротекста.
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <returns>Блок открытого текста.</returns>
        public byte[] DecodeProcess(byte[] data, List<uint> subKeys)
        {
            byte[] gamma = new byte[8];
            Array.Copy(BitConverter.GetBytes(n1), 0, gamma, 0, 4);
            Array.Copy(BitConverter.GetBytes(n2), 0, gamma, 4, 4);
            gamma = substitution.EncodeProcess(gamma, subKeys);

            byte[] res = XOR(gamma, data);

            if (data.Length == 8)
            {
                n1 = BitConverter.ToUInt32(data, 0);
                n2 = BitConverter.ToUInt32(data, 4);
            }
            
            return res;
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
