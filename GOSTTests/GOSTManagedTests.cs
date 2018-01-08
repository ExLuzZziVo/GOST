using GOST.Types;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace GOST.Tests
{
    [TestClass()]
    public class GOSTManagedTests
    {
        [TestMethod()]
        public void GOSTManagedTestFullKey()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890123456789012");
            byte[] message = Encoding.Default.GetBytes("message");
            var gost = new GOSTManaged(key, message, CipherTypes.Substitution);

            Console.WriteLine(Encoding.Default.GetString(gost.Key));
            Console.WriteLine(Encoding.Default.GetString(key));

            Assert.AreEqual(Encoding.Default.GetString(gost.Key), Encoding.Default.GetString(key));
            Assert.AreEqual(Encoding.Default.GetString(gost.Message), Encoding.Default.GetString(message));
        }
    }
}