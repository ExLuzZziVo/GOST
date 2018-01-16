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
        /// Первоначальная установка состояния шифра.
        /// </summary>
        /// <param name="synchroSignal">Синхропосылка.</param>
        /// <param name="subKeys">Подключи.</param>
        void SetSynchroSignal(byte[] synchroSignal, List<uint> subKeys);

        /// <summary>
        /// Процесс шифрования открытого текста
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <returns>64-х битный блок шифротекста.</returns>
        byte[] EncodeProcess(byte[] data, List<uint> subKeys);

        /// <summary>
        /// Процесс дешифровки шифротекста.
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <returns>64-х битный блок открытого текста.</returns>
        byte[] DecodeProcess(byte[] data, List<uint> subKeys);
    }
}
