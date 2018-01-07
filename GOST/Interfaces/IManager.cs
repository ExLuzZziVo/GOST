using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GOST.Interfaces
{
    interface IManager
    {
        /// <summary>
        /// Свойство - ключ.
        /// </summary>
        byte[] Key { get; set; }
        /// <summary>
        /// Свойство - сообщение.
        /// </summary>
        byte[] Message { get; set; }
        /// <summary>
        /// Шифрование.
        /// </summary>
        /// <returns>Результат шифрования.</returns>
        byte[] Encode();
        /// <summary>
        /// Шифрование подстановкой.
        /// </summary>
        /// <returns>Результат шифрования.</returns>
        byte[] SubstitutionEncode();
        /// <summary>
        /// Шифрование гаммированием.
        /// </summary>
        /// <returns>Результат шифрования.</returns>
        byte[] XOREncode();
        /// <summary>
        /// Шифрование гаммированием с обратной связью.
        /// </summary>
        /// <returns>Результат шифрования.</returns>
        byte[] ReverseXOREncode();
        /// <summary>
        /// Шифрование иммитовставкой.
        /// </summary>
        /// <returns>Результат шифрования.</returns>
        byte[] MACEncode();
    }
}
