using GOST.Types;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace GOST.Tests
{
    [TestClass()]
    public class GOSTManagedTests
    {
        [TestMethod()]
        public void GOSTManagedTest()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
            byte[] message = Encoding.Default.GetBytes("message");

            var gost = new GOSTManaged(key, message, CipherTypes.Substitution);

            Console.WriteLine(Encoding.Default.GetString(gost.Key));
            Console.WriteLine(Encoding.Default.GetString(key));

            Assert.AreEqual(Encoding.Default.GetString(gost.Key), Encoding.Default.GetString(key));
            Assert.AreEqual(Encoding.Default.GetString(gost.Message), Encoding.Default.GetString(message));
        }

        [TestMethod()]
        public void GetSubKeysTest()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
            byte[] message = Encoding.Default.GetBytes("message");

            var gost = new GOSTManaged(key, message, CipherTypes.Substitution);

            PrivateObject priv = new PrivateObject(gost);
            priv.Invoke("GetSubKeys");
            List<uint> keys = (List<uint>)priv.GetFieldOrProperty("subKeys");

            Assert.AreEqual(keys.Count, 32);
        }

        [TestMethod()]
        public void EncodeDecodeMessageTest()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
            byte[] message = Encoding.Default.GetBytes("1234567887654321");

            var gost = new GOSTManaged(key, message, CipherTypes.Substitution);
            var encode = gost.Encode();

            gost = new GOSTManaged(key, encode, CipherTypes.Substitution);
            var decode = gost.Decode();

            Assert.AreEqual(Encoding.Default.GetString(message), Encoding.Default.GetString(decode));
        }
    }
}