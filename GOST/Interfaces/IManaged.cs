using GOST.Types;

namespace GOST.Interfaces
{
    internal interface IManaged
    {
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
