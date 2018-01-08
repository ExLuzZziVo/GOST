using System.Collections;
using System.Collections.Generic;

namespace GOST.Interfaces
{
    internal interface ICipher
    {
        /// <summary>
        /// Процесс шифрования открытого текста
        /// </summary>
        /// <param name="data">64-х битный блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <returns>64-х битный блок шифротекста.</returns>
        byte[] EncodeProcess(byte[] data, List<uint> subKeys);

        /// <summary>
        /// Процесс дешифровки шифротекста.
        /// </summary>
        /// <param name="data">64-х битный блок шифротекста.</param>
        /// <param name="subKey">Подключ.</param>
        /// <returns>64-х битный блок открытого текста.</returns>
        byte[] DecodeProcess(byte[] data, List<uint> subKeys);
    }
}
