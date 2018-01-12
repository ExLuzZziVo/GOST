using Microsoft.VisualStudio.TestTools.UnitTesting;
using GOST.Ciphers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;
using GOST.Interfaces;
using GOST.SBlocks;
using GOST.Types;

namespace GOST.Ciphers.Tests
{
    [TestClass()]
    public class SubstitutionCipherTests
    {
        [TestMethod()]
        public void SubstitutionCipherTest()
        {
            var cipher = new SubstitutionCipher(new GOSTBlock());
        }

        [TestMethod()]
        public void EncodeDecodeBlockTest()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
            byte[] message = Encoding.Default.GetBytes("message");

            var gost = new GOSTManaged
            {
                Key = key
            };

            PrivateObject priv = new PrivateObject(gost);
            priv.Invoke("GetSubKeys");
            List<uint> keys = (List<uint>)priv.GetFieldOrProperty("subKeys");

            byte[] data = Encoding.Default.GetBytes("12345678");
            var cipher = new SubstitutionCipher(new GOSTBlock());
            var encode = cipher.EncodeProcess(data, keys);
            Assert.AreEqual(encode.Length, 8);

            keys.Reverse();
            var decode = cipher.DecodeProcess(encode, keys);
            Assert.AreEqual(Encoding.Default.GetString(data), Encoding.Default.GetString(decode));
        }
    }
}