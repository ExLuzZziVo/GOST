namespace GOST.Interfaces
{
    internal interface ICipher
    {
        /// <summary>
        /// Процесс шифрования открытого текста
        /// </summary>
        /// <param name="data">64-х битный блок открытого текста.</param>
        /// <param name="subKey">Подключ.</param>
        /// <returns>64-х битный блок шифротекста.</returns>
        byte[] EncodeProcess(byte[] data, byte[] subKey);
    }
}
