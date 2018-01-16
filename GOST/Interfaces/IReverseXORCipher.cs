using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GOST.Interfaces
{
    internal interface IReverseXORCipher
    {
        /// <summary>
        /// Первоначальная установка состояния шифра.
        /// </summary>
        /// <param name="synchroSignal">Синхропосылка.</param>
        void SetSynchroSignal(byte[] synchroSignal);

        /// <summary>
        /// Процесс шифрования открытого текста
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <returns>Блок шифротекста.</returns>
        byte[] EncodeProcess(byte[] data, List<uint> subKeys);

        /// <summary>
        /// Процесс дешифровки шифротекста.
        /// </summary>
        /// <param name="data">Блок открытого текста.</param>
        /// <param name="subKey">Коллекция подключей.</param>
        /// <returns>Блок открытого текста.</returns>
        byte[] DecodeProcess(byte[] data, List<uint> subKeys);
    }
}
