using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GOST.Interfaces
{
    internal interface ISubstitutionCipher
    {
        /// <summary>
        /// Процесс шифрования открытого текста
        /// </summary>
        /// <param name="data">64-х битный блок открытого текста.</param>
        /// <param name="subKeys">Коллекция подключей.</param>
        /// <returns>64-х битный блок шифротекста.</returns>
        byte[] EncodeProcess(byte[] data, List<uint> subKeys);

        /// <summary>
        /// Процесс дешифровки шифротекста.
        /// </summary>
        /// <param name="data">64-х битный блок шифротекста.</param>
        /// <param name="subKey">Подключ.</param>
        /// <returns>64-х битный блок открытого текста.</returns>
        byte[] DecodeProcess(byte[] data, List<uint> subKeys);

        /// <summary>
        /// Основная функция шифрования.
        /// </summary>
        /// <param name="littleBits">Младшие биты.</param>
        /// <param name="subKey">Подключ.</param>
        /// <returns>Результат шифрования функцией.</returns>
        uint Function(uint block, uint subKey);

        /// <summary>
        /// Подстановка.
        /// </summary>
        /// <param name="block">Блок для подстановки.</param>
        /// <returns>Блок после подстановки.</returns>
        uint Substitute(uint value);
    }
}
