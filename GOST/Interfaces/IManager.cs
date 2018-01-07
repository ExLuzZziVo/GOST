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
    }
}
