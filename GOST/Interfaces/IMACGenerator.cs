#region

using System.Collections.Generic;

#endregion

namespace GOST.Interfaces
{
    internal interface IMACGenerator
    {
        /// <summary>
        ///     MAC generator.
        /// </summary>
        /// <param name="data">Message.</param>
        /// <param name="subKeys">Subkeys.</param>
        /// <returns>MAC.</returns>
        byte[] Process(byte[] data, List<uint> subKeys);
    }
}