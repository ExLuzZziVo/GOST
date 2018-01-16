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

            var gost = new GOSTManaged
            {
                Key = key,
                Message = message
            };

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

            var gost = new GOSTManaged
            {
                Key = key
            };

            PrivateObject priv = new PrivateObject(gost);
            priv.Invoke("GetSubKeys");
            List<uint> keys = (List<uint>)priv.GetFieldOrProperty("subKeys");

            Assert.AreEqual(keys.Count, 32);
        }

        [TestMethod()]
        public void SubstitutionEncodeDecodeMessageTest()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
            byte[] message = Encoding.Default.GetBytes("1234567887654321");

            byte[] encode = new byte[16];
            byte[] decode = new byte[16];

            using (var gost = new GOSTManaged())
            {
                encode = gost.SubstitutionEncode(key, message);
            }

            using (var gost = new GOSTManaged())
            {
                decode = gost.SubstitutionDecode(key, encode);
            }

            Assert.AreEqual(Encoding.Default.GetString(message), Encoding.Default.GetString(decode));
        }

        [TestMethod()]
        public void XOREncodeDecodeMessageTest()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
            byte[] synchro = Encoding.Default.GetBytes("12345678");
            byte[] message = Encoding.Default.GetBytes("12345678876543");

            byte[] encode = new byte[14];
            byte[] decode = new byte[14];

            using (var gost = new GOSTManaged())
            {
                encode = gost.XOREncode(key, synchro, message);
            }

            using (var gost = new GOSTManaged())
            {
                decode = gost.XORDecode(key, synchro, encode);
            }

            Assert.AreEqual(Encoding.Default.GetString(message), Encoding.Default.GetString(decode));
        }

        [TestMethod()]
        public void PerfomanceSubstitutionEncodeDecodeMessageTest()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
            byte[] message = new byte[100000000];

            var rand = new Random();

            for (int i = 0; i != 100000000; i++)
            {
                message[i] = Convert.ToByte(rand.Next(9));
            }

            byte[] encode = new byte[100000000];
            byte[] decode = new byte[100000000];

            using (var gost = new GOSTManaged())
            {
                encode = gost.SubstitutionEncode(key, message);
            }

            using (var gost = new GOSTManaged())
            {
                decode = gost.SubstitutionDecode(key, encode);
            }

            Assert.AreEqual(Encoding.Default.GetString(message), Encoding.Default.GetString(decode));
        }

        [TestMethod()]
        public void PerfomanceXOREncodeDecodeMessageTest()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
            byte[] synchro = Encoding.Default.GetBytes("12345678");
            byte[] message = new byte[99999997];

            var rand = new Random();

            for (int i = 0; i != 99999997; i++)
            {
                message[i] = Convert.ToByte(rand.Next(9));
            }

            byte[] encode = new byte[99999997];
            byte[] decode = new byte[99999997];

            using (var gost = new GOSTManaged())
            {
                encode = gost.XOREncode(key, synchro, message);
            }

            using (var gost = new GOSTManaged())
            {
                decode = gost.XORDecode(key, synchro, encode);
            }

            Assert.AreEqual(Encoding.Default.GetString(message), Encoding.Default.GetString(decode));
        }
    }
}