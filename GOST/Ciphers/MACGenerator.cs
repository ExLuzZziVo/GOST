using GOST.Interfaces;
using System;
using System.Collections.Generic;

namespace GOST.Ciphers
{
    internal class MACGenerator : IMACGenerator
    {
        private uint n1;
        private uint n2;

        private byte[] round;

        private ISBlocks sBlock;

        public MACGenerator(ISBlocks sBlock)
        {
            this.sBlock = sBlock;
        }

        /// <summary>
        /// MAC generator.
        /// </summary>
        /// <param name="data">Message.</param>
        /// <param name="subKeys">Subkeys.</param>
        /// <returns>MAC.</returns>
        public byte[] Process(byte[] data, List<uint> subKeys)
        {
            if (data.Length != 8)
            {
                byte[] temp = new byte[8];
                Array.Copy(data, 0, temp, 0, data.Length);
                for (int i = data.Length - 1; i != 8; i++)
                {
                    temp[i] = 0;
                }
                data = temp;
            }

            if (round == null)
            {
                n1 = BitConverter.ToUInt32(data, 0);
                n2 = BitConverter.ToUInt32(data, 4);

                round = ShortSubstitute(n1, n2, subKeys);
            }
            else if (round != null)
            {
                for (int i = 0; i != 8; i++)
                {
                    round[i] = (byte)(round[i] ^ data[i]);
                }

                n1 = BitConverter.ToUInt32(round, 0);
                n2 = BitConverter.ToUInt32(round, 4);

                round = ShortSubstitute(n1, n2, subKeys);
            }

            return round;
        }

        /// <summary>
        /// 16-round version of substitution cipher.
        /// </summary>
        /// <param name="little">Little bits.</param>
        /// <param name="big">Big bits.</param>
        /// <param name="subKeys">Subkeys.</param>
        /// <returns>Result.</returns>
        private byte[] ShortSubstitute(uint little, uint big, List<uint> subKeys)
        {
            for (int i = 0; i != 16; i++)
            {
                var round = big ^ Function(little, subKeys[i]);

                big = little;
                little = round;
            }

            byte[] result = new byte[8];
            Array.Copy(BitConverter.GetBytes(little), 0, result, 0, 4);
            Array.Copy(BitConverter.GetBytes(big), 0, result, 4, 4);
            return result;
        }

        /// <summary>
        /// Main func.
        /// </summary>
        /// <param name="block">Little bits.</param>
        /// <param name="subKey">Subkeys.</param>
        /// <returns>Result.</returns>
        private uint Function(uint block, uint subKey)
        {
            block = (block + subKey) % 4294967295;
            block = Substitute(block);
            block = (block << 11) | (block >> 21);
            return block;
        }

        /// <summary>
        /// Substitution.
        /// </summary>
        /// <param name="value">Block for substitution.</param>
        /// <returns>Result.</returns>
        private uint Substitute(uint value)
        {
            uint res = 0;

            for (int i = 0; i != 8; i++)
            {
                byte index = (byte)(value >> (4 * i) & 0x0f);
                byte block = sBlock.SBlockTable[i][index];
                res |= (uint)block << (4 * i);
            }

            return res;
        }
    }
}
