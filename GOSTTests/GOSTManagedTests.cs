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

            var gost = new GOSTManaged();

            PrivateObject priv = new PrivateObject(gost);
            priv.SetFieldOrProperty("Key", key);
            priv.SetFieldOrProperty("Message", message);

            Assert.AreEqual(Encoding.Default.GetString((byte[])priv.GetFieldOrProperty("Key")), Encoding.Default.GetString(key));
            Assert.AreEqual(Encoding.Default.GetString((byte[])priv.GetFieldOrProperty("Message")), Encoding.Default.GetString(message));
        }

        [TestMethod()]
        public void GetSubKeysTest()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
            byte[] message = Encoding.Default.GetBytes("message");

            var gost = new GOSTManaged();

            PrivateObject priv = new PrivateObject(gost);
            priv.SetFieldOrProperty("Key", key);
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
        public void CFBEncodeDecodeMessageTest()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
            byte[] synchro = Encoding.Default.GetBytes("12345678");
            byte[] message = Encoding.Default.GetBytes("12345678876543");

            byte[] encode = new byte[14];
            byte[] decode = new byte[14];

            using (var gost = new GOSTManaged())
            {
                encode = gost.CFBEncode(key, synchro, message);
            }

            using (var gost = new GOSTManaged())
            {
                decode = gost.CFBDecode(key, synchro, encode);
            }

            Assert.AreEqual(Encoding.Default.GetString(message), Encoding.Default.GetString(decode));
        }

        [TestMethod()]
        public void MACGeneratorTest()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
            byte[] message1 = Encoding.Default.GetBytes("1234567887654321");
            byte[] message2 = Encoding.Default.GetBytes("2234567887654321");
            byte[] message3 = Encoding.Default.GetBytes("3456788765432");

            byte[] mac1 = new byte[8];
            byte[] mac2 = new byte[8];
            byte[] mac3 = new byte[8];

            using (var gost = new GOSTManaged())
            {
                mac1 = gost.MACGenerator(key, message1);
                mac2 = gost.MACGenerator(key, message2);
                mac3 = gost.MACGenerator(key, message3);
            }

            Assert.AreNotEqual(mac1, mac2);
            Assert.AreEqual(mac3.Length, 8);
        }

        [TestMethod()]
        public void PerformanceSubstitutionEncodeDecodeMessageTest()
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
        public void PerformanceXOREncodeDecodeMessageTest()
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

        [TestMethod()]
        public void PerformanceReverseCFBEncodeDecodeMessageTest()
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
                encode = gost.CFBEncode(key, synchro, message);
            }

            using (var gost = new GOSTManaged())
            {
                decode = gost.CFBDecode(key, synchro, encode);
            }

            Assert.AreEqual(Encoding.Default.GetString(message), Encoding.Default.GetString(decode));
        }
    }
}