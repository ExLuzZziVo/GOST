using System.Collections.Generic;

namespace GOST.Interfaces
{
    internal interface ICFBCipher
    {
        /// <summary>
        /// Set generator state.
        /// </summary>
        /// <param name="synchroSignal">IV</param>
        void SetIV(byte[] iv);

        /// <summary>
        /// CFB encode.
        /// </summary>
        /// <param name="data">Opened message.</param>
        /// <param name="subKey">Subkeys.</param>
        /// <returns>Encoded message.</returns>
        byte[] EncodeProcess(byte[] data, List<uint> subKeys);

        /// <summary>
        /// CFB decode.
        /// </summary>
        /// <param name="data">Encoded message.</param>
        /// <param name="subKey">Subkeys.</param>
        /// <returns>Opened message.</returns>
        byte[] DecodeProcess(byte[] data, List<uint> subKeys);
    }
}
