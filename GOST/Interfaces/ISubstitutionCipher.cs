using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GOST.Interfaces
{
    internal interface ISubstitutionCipher : ICipher
    {
        
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
