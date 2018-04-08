using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Gabriel.Cat.S.Seguretat;
namespace TestGabrielCatSSeguretat
{
    [TestClass]
    public class TestCesar
    {
        
        [TestMethod]
        public void TestCesarEncryptDecryptBytes()
        {
            Assert.IsTrue(Test.TestMethodBytes(Cesar.Encrypt,Cesar.Decrypt));
        }

        [TestMethod]
        public void TestCesarEncryptDecryptString()
        {
            Assert.IsTrue(Test.TestMethodString((text,password,level,ordre)=>StringEncrypt.Encrypt(text,password,DataEncrypt.Cesar,level,PasswordEncrypt.Nothing,ordre), (text, password, level, ordre) => StringEncrypt.Decrypt(text, password, DataEncrypt.Cesar, level, PasswordEncrypt.Nothing, ordre)));
        }
    }
}
