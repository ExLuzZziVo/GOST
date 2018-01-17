using GOST.Interfaces;
using System;
using System.Collections.Generic;

namespace GOST.Ciphers
{
    internal class CFBCipher : ICFBCipher
    {
        private uint n1;
        private uint n2;

        private SubstitutionCipher substitution;

        public CFBCipher(ISBlocks sBlock)
        {
            substitution = new SubstitutionCipher(sBlock);
        }

        /// <summary>
        /// Set generator state.
        /// </summary>
        /// <param name="synchroSignal">IV</param>
        public void SetIV(byte[] synchroSignal)
        {
            n1 = BitConverter.ToUInt32(synchroSignal, 0);
            n2 = BitConverter.ToUInt32(synchroSignal, 4);
        }

        /// <summary>
        /// CFB encode.
        /// </summary>
        /// <param name="data">Opened message.</param>
        /// <param name="subKeys">Subkeys.</param>
        /// <returns>Encoded message.</returns>
        public byte[] EncodeProcess(byte[] data, List<uint> subKeys)
        {
            byte[] gamma = new byte[8];
            Array.Copy(BitConverter.GetBytes(n1), 0, gamma, 0, 4);
            Array.Copy(BitConverter.GetBytes(n2), 0, gamma, 4, 4);
            gamma = substitution.EncodeProcess(gamma, subKeys);

            byte[] res = XOR(gamma, data);

            if (res.Length == 8)
            {
                n1 = BitConverter.ToUInt32(res, 0);
                n2 = BitConverter.ToUInt32(res, 4);
            }

            return res;
        }

        /// <summary>
        /// CFB decode.
        /// </summary>
        /// <param name="data">Encoded message.</param>
        /// <param name="subKeys">Subkeys.</param>
        /// <returns>Opened message.</returns>
        public byte[] DecodeProcess(byte[] data, List<uint> subKeys)
        {
            byte[] gamma = new byte[8];
            Array.Copy(BitConverter.GetBytes(n1), 0, gamma, 0, 4);
            Array.Copy(BitConverter.GetBytes(n2), 0, gamma, 4, 4);
            gamma = substitution.EncodeProcess(gamma, subKeys);

            byte[] res = XOR(gamma, data);

            if (data.Length == 8)
            {
                n1 = BitConverter.ToUInt32(data, 0);
                n2 = BitConverter.ToUInt32(data, 4);
            }
            
            return res;
        }

        /// <summary>
        /// XOR
        /// </summary>
        /// <param name="gamma">Gamma.</param>
        /// <param name="data">Data.</param>
        /// <returns>XOR result..</returns>
        private byte[] XOR(byte[] gamma, byte[] data)
        {
            int len = data.Length;
            byte[] res = new byte[len];

            for (int i = 0; i != len; i++)
            {
                res[i] = (byte)(gamma[i] ^ data[i]);
            }

            return res;
        }
    }
}
