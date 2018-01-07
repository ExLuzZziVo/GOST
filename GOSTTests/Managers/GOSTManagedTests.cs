using Microsoft.VisualStudio.TestTools.UnitTesting;
using GOST;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using GOST.Types;

namespace GOST.Tests
{
    [TestClass()]
    public class GOSTManagedTests
    {
        [TestMethod()]
        public void GOSTManagedTest1()
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
        public void GOSTManagedTest2()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890");
            byte[] message = Encoding.Default.GetBytes("message");
            var gost = new GOSTManaged(key, message, CipherTypes.Substitution);

            byte[] waitKey = Encoding.Default.GetBytes("12345678901234567890");
            for (int i = waitKey.Length; i != 32; i++)
            {
                var newKey = new byte[waitKey.Length + 1];
                waitKey.CopyTo(newKey, 0);
                newKey[newKey.Length - 1] = 0;
                waitKey = newKey;
            }

            Console.WriteLine(Encoding.Default.GetString(gost.Key));
            Console.WriteLine(Encoding.Default.GetString(waitKey));

            Assert.AreEqual(Encoding.Default.GetString(gost.Key), Encoding.Default.GetString(waitKey));
            Assert.AreEqual(gost.Key.Length, 32);
            Assert.AreEqual(Encoding.Default.GetString(gost.Message), Encoding.Default.GetString(message));
        }
    }
}