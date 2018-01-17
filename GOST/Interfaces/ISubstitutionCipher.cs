using System.Collections.Generic;

namespace GOST.Interfaces
{
    internal interface ISubstitutionCipher
    {
        /// <summary>
        /// Substitution encode.
        /// </summary>
        /// <param name="data">Opened message multiple of 64 bits.</param>
        /// <param name="subKeys">Subkeys.</param>
        /// <returns>Encoded message multiple of 64 bits.</returns>
        byte[] EncodeProcess(byte[] data, List<uint> subKeys);

        /// <summary>
        /// Substitution decode.
        /// </summary>
        /// <param name="data">Encoded message multiple of 64 bits.</param>
        /// <param name="subKeys">Subkeys.</param>
        /// <returns>Opened message multiple of 64 bits.</returns>
        byte[] DecodeProcess(byte[] data, List<uint> subKeys);

        /// <summary>
        /// Main func.
        /// </summary>
        /// <param name="block">Little bits.</param>
        /// <param name="subKey">Subkeys.</param>
        /// <returns>Result.</returns>
        uint Function(uint block, uint subKey);

        /// <summary>
        /// Substitution.
        /// </summary>
        /// <param name="block">Block for substitution.</param>
        /// <returns>Result.</returns>
        uint Substitute(uint value);
    }
}
