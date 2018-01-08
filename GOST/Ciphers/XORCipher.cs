using GOST.Interfaces;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GOST.Ciphers
{
    internal class XORCipher : IXORCipher
    {
        public byte[] DecodeProcess(byte[] data, List<uint> subKeys)
        {
            throw new NotImplementedException();
        }

        public byte[] EncodeProcess(byte[] data, List<uint> subKeys)
        {
            throw new NotImplementedException();
        }
    }
}
