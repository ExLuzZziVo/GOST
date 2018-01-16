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

        /// <summary>
        /// Шифрование гаммированием.
        /// </summary>
        /// <param name="key">256 битный ключ.</param>
        /// <param name="synchroSignal">64 битная шифропосылка.</param>
        /// <param name="message">Открытые данные.</param>
        /// <param name="sBlockType">Таблица шифрования</param>
        /// <returns>Зашифрованные данные.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        byte[] XOREncode(byte[] key, byte[] synchroSignal, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);

        /// <summary>
        /// Дешифрование гаммированием.
        /// </summary>
        /// <param name="key">256 битный ключ.</param>
        /// <param name="synchroSignal">64 битная шифропосылка.</param>
        /// <param name="message">Шифроданные.</param>
        /// <param name="sBlockType">Таблица шифрования</param>
        /// <returns>Открытые данные.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        byte[] XORDecode(byte[] key, byte[] synchroSignal, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);

        /// <summary>
        /// Шифрование гаммированием с обратной связью
        /// </summary>
        /// <param name="key">256 битный ключ.</param>
        /// <param name="synchroSignal">64 битная шифропосылка.</param>
        /// <param name="message">Открытые данные.</param>
        /// <param name="sBlockType">Таблица шифрования</param>
        /// <returns>Зашифрованные данные.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        byte[] ReverseXOREncode(byte[] key, byte[] synchroSignal, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);

        /// <summary>
        /// Дешифрование гаммированием с обратной связью
        /// </summary>
        /// <param name="key">256 битный ключ.</param>
        /// <param name="synchroSignal">64 битная шифропосылка.</param>
        /// <param name="message">Шифроданные.</param>
        /// <param name="sBlockType">Таблица шифрования</param>
        /// <returns>Открытые данные.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        byte[] ReverseXORDecode(byte[] key, byte[] synchroSignal, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);
    }
}
