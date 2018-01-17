using GOST.Types;

namespace GOST.Interfaces
{
    internal interface IManaged
    {
        /// <summary>
        /// Substitution encode.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="message">Opened message multiple of 64 bit.</param>
        /// <param name="sBlockType">STable.</param>
        /// <returns>Encoded message.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        byte[] SubstitutionEncode(byte[] key, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);

        /// <summary>
        /// Substitution decode.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="message">Encoded message multiple of 64 bit.</param>
        /// <param name="sBlockType">STable.</param>
        /// <returns>Opened message</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        byte[] SubstitutionDecode(byte[] key, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);

        /// <summary>
        /// XOR encode.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="iv">64 bit IV</param>
        /// <param name="message">Opened message.</param>
        /// <param name="sBlockType">STable.</param>
        /// <returns>Encoded message.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        byte[] XOREncode(byte[] key, byte[] synchroSignal, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);

        /// <summary>
        /// XOR decode.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="iv">64 bit IV</param>
        /// <param name="message">Encoded message.</param>
        /// <param name="sBlockType">STable.</param>
        /// <returns>Opened message.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        byte[] XORDecode(byte[] key, byte[] synchroSignal, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);

        /// <summary>
        /// CFB encode.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="iv">64 bit IV</param>
        /// <param name="message">Opened message.</param>
        /// <param name="sBlockType">STable.</param>
        /// <returns>Encoded message.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        byte[] CFBEncode(byte[] key, byte[] synchroSignal, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);

        /// <summary>
        /// CFB decode.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="iv">64 bit IV</param>
        /// <param name="message">Encoded message.</param>
        /// <param name="sBlockType">STable.</param>
        /// <returns>Opened message.</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        byte[] CFBDecode(byte[] key, byte[] synchroSignal, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);

        /// <summary>
        /// MAC generator.
        /// </summary>
        /// <param name="key">256 bit key.</param>
        /// <param name="message">Message (not less than 2 blocks).</param>
        /// <param name="sBlockType">SBlock.</param>
        /// <returns>MAC.</returns>
        byte[] MACGenerator(byte[] key, byte[] message, SBlockTypes sBlockType = SBlockTypes.GOST);
    }
}
