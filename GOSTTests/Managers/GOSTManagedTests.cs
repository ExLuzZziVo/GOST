using Microsoft.VisualStudio.TestTools.UnitTesting;
using GOST.Managers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using GOST.Types;

namespace GOST.Managers.Tests
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
            Assert.AreEqual(gost.Key, key);
        }

        [TestMethod()]
        public void GOSTManagedTest2()
        {
            byte[] key = Encoding.Default.GetBytes("12345678901234567890");
            byte[] message = Encoding.Default.GetBytes("message");
            var gost = new GOSTManaged(key, message, CipherTypes.Substitution);
            Assert.AreEqual(gost.Key.Length, 32);
        }
    }
}