using System.Collections.Generic;

namespace GOST.Interfaces
{
    internal interface IXORCipher
    {
        /// <summary>
        /// Первоначальная установка состояния шифра.
        /// </summary>
        /// <param name="iv">Синхропосылка.</param>
        /// <param name="subKeys">Подключи.</param>
        void SetIV(byte[] iv, List<uint> subKeys);

        /// <summary>
        /// Процесс шифрования открытого текста
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKeys">Коллекция подключей.</param>
        /// <returns>Блок шифротекста.</returns>
        byte[] EncodeProcess(byte[] data, List<uint> subKeys);

        /// <summary>
        /// Процесс дешифровки шифротекста.
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKeys">Коллекция подключей.</param>
        /// <returns>Блок открытого текста.</returns>
        byte[] DecodeProcess(byte[] data, List<uint> subKeys);
    }
}
