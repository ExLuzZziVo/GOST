using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GOST.Interfaces
{
    internal interface IXORCipher
    {
        /// <summary>
        /// Процесс шифрования открытого текста
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <param name="synchrosignal">64-х битная шифропосылка.</param>
        /// <returns>64-х битный блок шифротекста.</returns>
        byte[] EncodeProcess(byte[] data, List<uint> subKeys, byte[] synchrosignal);

        /// <summary>
        /// Процесс дешифровки шифротекста.
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <param name="synchrosignal">64-х битная шифропосылка.</param>
        /// <returns>64-х битный блок открытого текста.</returns>
        byte[] DecodeProcess(byte[] data, List<uint> subKeys, byte[] synchrosignal);
    }
}
