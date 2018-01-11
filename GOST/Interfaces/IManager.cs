namespace GOST.Interfaces
{
    internal interface IManager
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
        /// Дешифрование.
        /// </summary>
        /// <returns>Результат дешифрования.</returns>
        byte[] Decode();
    }
}
