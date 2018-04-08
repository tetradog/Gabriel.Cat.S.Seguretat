using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Gabriel.Cat.S.Seguretat;
namespace TestGabrielCatSSeguretat.TestingMetodosCifrar
{
    [TestClass]
    public class TestPerdut
    {

        [TestMethod]
        public void TestPerdutEncryptDecryptBytes()
        {
            Assert.IsTrue(Test.TestMethodBytes(Perdut.Encrypt,Perdut.Decrypt));
        }

        [TestMethod]
        public void TestPerdutEncryptDecryptString()
        {
            Assert.IsTrue(Test.TestMethodString((text, password, level, ordre) => StringEncrypt.Encrypt(text, password, DataEncrypt.Perdut, level, PasswordEncrypt.Nothing, ordre), (text, password, level, ordre) => StringEncrypt.Decrypt(text, password, DataEncrypt.Perdut, level, PasswordEncrypt.Nothing, ordre)));
        }
    }
}
