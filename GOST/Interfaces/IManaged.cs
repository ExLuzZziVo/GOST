using GOST.Types;

namespace GOST.Interfaces
{
    internal interface IManaged
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
        byte[] SubstitutionEncode(byte[] key, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);

        /// <summary>
        /// Дешифрование.
        /// </summary>
        /// <returns>Результат дешифрования.</returns>
        byte[] SubstitutionDecode(byte[] key, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);
    }
}
