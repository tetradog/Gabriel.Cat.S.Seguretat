using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Gabriel.Cat.S.Seguretat;
namespace TestGabrielCatSSeguretat.TestingMetodosCifrar
{
    [TestClass]
    public class TestDisimulat
    {

        [TestMethod]
        public void TestDisimulatEncryptDecryptBytes()
        {
            Assert.IsTrue(Test.TestMethodBytes(Disimulat.Encrypt, Disimulat.Decrypt));
        }

        [TestMethod]
        public void TestDisimulatEncryptDecryptString()
        {
            const LevelEncrypt MAXLEVEL = LevelEncrypt.Normal;
            bool correcto;
            int posInicial = new Random().Next(byte.MaxValue+1)*byte.MaxValue;

                correcto = Test.TestMethodString((text, password, level, ordre) => StringEncrypt.Encrypt(text, password, DataEncrypt.Disimulat, level, PasswordEncrypt.Nothing, ordre), (text, password, level, ordre) => StringEncrypt.Decrypt(text, password, DataEncrypt.Disimulat, level, PasswordEncrypt.Nothing, ordre), byte.MaxValue + 1,posInicial,MAXLEVEL);

            //requiere mucha memoria...lo ideal seria probarlo char.Length+1...pero creo que se dispara mucho la memoria...
            Assert.IsTrue(correcto);
        }
    }
}