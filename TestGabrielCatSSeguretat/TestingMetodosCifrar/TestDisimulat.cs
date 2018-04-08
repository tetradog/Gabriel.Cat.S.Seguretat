﻿using System;
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
            Assert.IsTrue(Test.TestMethodString((text, password, level, ordre) => StringEncrypt.Encrypt(text, password, DataEncrypt.Disimulat, level, PasswordEncrypt.Nothing, ordre), (text, password, level, ordre) => StringEncrypt.Decrypt(text, password, DataEncrypt.Disimulat, level, PasswordEncrypt.Nothing, ordre)));
        }
    }
}