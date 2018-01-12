using GOST.Interfaces;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("GOSTTests")]

namespace GOST.Ciphers
{
    internal class XORCipher : IXORCipher
    {
        private SubstitutionCipher substitution;

        public XORCipher(ISBlocks sBlock)
        {
            substitution = new SubstitutionCipher(sBlock);
        }

        /// <summary>
        /// Процесс шифрования открытого текста
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <param name="synchrosignal">64-х битная шифропосылка.</param>
        /// <returns>64-х битный блок шифротекста.</returns>
        public byte[] EncodeProcess(byte[] data, List<uint> subKeys, byte[] synchrosignal)
        {
            // Шифропосылка шифруется методом подстановки.
            byte[] encodedSynchroSignal = substitution.EncodeProcess(synchrosignal, subKeys);
            return new byte[] { 1 };
        }

        /// <summary>
        /// Процесс дешифровки шифротекста.
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <param name="synchrosignal">64-х битная шифропосылка.</param>
        /// <returns>64-х битный блок открытого текста.</returns>
        public byte[] DecodeProcess(byte[] data, List<uint> subKeys, byte[] synchrosignal)
        {
            throw new NotImplementedException();
        }
    }
}
