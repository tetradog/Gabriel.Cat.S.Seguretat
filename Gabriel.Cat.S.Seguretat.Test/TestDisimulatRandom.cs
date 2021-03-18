using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Gabriel.Cat.S.Seguretat.Test
{
    [TestClass]
    public class DisimulatRandom
    {
        [TestMethod]
        public void TestDisimulatRandomEncryptDecryptSync()
        {
            byte[] dataEncrypted;

            LevelEncrypt level = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal =Serializar.GetBytes(Resource.imagen);
            
            Context<byte> context = DisimulatRandomMethod.Encrypt(dataOriginal,password, level);
            dataEncrypted = context.Output;
            context = DisimulatRandomMethod.Decrypt(dataEncrypted, password, level);
            Assert.IsTrue(dataOriginal.AreEquals(context.Output));


        }
        [TestMethod]
        public async Task TestDisimulatRandomEncryptDecryptASync()
        {
            byte[] dataEncrypted;
            Task task;
            LevelEncrypt level = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Serializar.GetBytes(Resource.imagen);
            StopProcess stopProcess = new StopProcess() { Continue = false };
            Context<byte> context = DisimulatRandomMethod.Encrypt(dataOriginal, password, level, stopProcess);
            Action act = () =>
            {
                while(!context.Acabado)
                    DisimulatRandomMethod.Encrypt(context, password, level, stopProcess);
            };
            stopProcess.Continue = true;
            task = Task.Run(act);

            task.Wait(150);
            stopProcess.Continue = false;
            task.Wait(1500);
            stopProcess.Continue = true;
            await task;
          
            dataEncrypted = context.Output;
            context = DisimulatRandomMethod.Decrypt(dataEncrypted, password, level, stopProcess);

            Assert.IsTrue(dataOriginal.AreEquals(context.Output));


        }
        [TestMethod]
        public async Task TestDisimulatRandomEncryptDecryptASyncPartes()
        {
            const int BUFFER = 1024 * 512;
            const EncryptMethod METHOD = EncryptMethod.DisimulatRandom;
            const LevelEncrypt LEVEL = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Serializar.GetBytes(Resource.imagen);
            await Cesar.EncryptDecryptPartesCommon(METHOD, LEVEL, password, dataOriginal, BUFFER);
        }
        [TestMethod]
        public async Task TestDisimulatRandomEncryptDecryptASyncParte()
        {
            const int BUFFER = -1;
            const EncryptMethod METHOD = EncryptMethod.DisimulatRandom;
            const LevelEncrypt LEVEL = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Serializar.GetBytes(Resource.imagen);
            await Cesar.EncryptDecryptPartesCommon(METHOD, LEVEL, password, dataOriginal, BUFFER);
        }
        [TestMethod]
        public async Task TestDisimulatRandomEncryptDecryptASyncPartesArchivoGrande()
        {
            const int BUFFER = 1024 * 512;
            const EncryptMethod METHOD = EncryptMethod.DisimulatRandom;
            const LevelEncrypt LEVEL = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Resource.grande;
            await Cesar.EncryptDecryptPartesCommon(METHOD, LEVEL, password, dataOriginal, BUFFER);
        }
        [TestMethod]
        public async Task TestDisimulatRandomEncryptDecryptASyncParteArchivoGrande()
        {
            const int BUFFER = -1;
            const EncryptMethod METHOD = EncryptMethod.DisimulatRandom;
            const LevelEncrypt LEVEL = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Resource.grande;
            await Cesar.EncryptDecryptPartesCommon(METHOD, LEVEL, password, dataOriginal, BUFFER);
        }
    }
}
