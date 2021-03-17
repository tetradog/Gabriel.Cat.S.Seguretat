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
    public class Cesar
    {
        [TestMethod]
        public void TestCesarEncryptDecryptSync()
        {
            byte[] dataEncrypted;

            LevelEncrypt level = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal =Serializar.GetBytes(Resource.imagen);
            
            Context<byte> context = CesarMethod.InitCesar(dataOriginal);
            CesarMethod.Encrypt(context,password, level, new StopProcess());
            dataEncrypted = context.Output;
            context = CesarMethod.InitCesar(dataEncrypted);
            CesarMethod.Decrypt(context,password,level,new StopProcess());
            Assert.IsTrue(dataOriginal.AreEquals(context.Output));


        }
        [TestMethod]
        public async Task TestCesarEncryptDecryptASync()
        {
            byte[] dataEncrypted;

            LevelEncrypt level = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Serializar.GetBytes(Resource.imagen);
            StopProcess stopProcess = new StopProcess();
            Context<byte> context = CesarMethod.InitCesar(dataOriginal);
            Action act = () =>
            {
                while(!context.Acabado)
                  CesarMethod.Encrypt(context, password, level, stopProcess);
            };
            Task task = Task.Run(act);

            task.Wait(150);
            stopProcess.Continue = false;
            task.Wait(1500);
            stopProcess.Continue = true;
            await task;
          
            dataEncrypted = context.Output;
            context = CesarMethod.InitCesar(dataEncrypted);
            CesarMethod.Decrypt(context, password, level, stopProcess);
            Assert.IsTrue(dataOriginal.AreEquals(context.Output));


        }
        [TestMethod]
        public async Task TestCesarEncryptDecryptASyncPartes()
        {
            const int BUFFER = 1024 * 512;
            const EncryptMethod METHOD = EncryptMethod.Cesar;
            const LevelEncrypt LEVEL = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Serializar.GetBytes(Resource.imagen);
            await Cesar.EncryptDecryptPartesCommon(METHOD, LEVEL, password, dataOriginal, BUFFER);
        }
        [TestMethod]
        public async Task TestCesarEncryptDecryptASyncParte()
        {
            const int BUFFER = -1;
            const EncryptMethod METHOD = EncryptMethod.Cesar;
            const LevelEncrypt LEVEL = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Serializar.GetBytes(Resource.imagen);
            await Cesar.EncryptDecryptPartesCommon(METHOD, LEVEL, password, dataOriginal, BUFFER);
        }
        [TestMethod]
        public async Task TestPerdutEncryptDecryptASyncPartesArchivoGrande()
        {
            const int BUFFER = 1024 * 512;
            const EncryptMethod METHOD = EncryptMethod.Cesar;
            const LevelEncrypt LEVEL = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal =Resource.grande;
            await Cesar.EncryptDecryptPartesCommon(METHOD, LEVEL, password, dataOriginal, BUFFER);
        }
        [TestMethod]
        public async Task TestPerdutEncryptDecryptASyncParteArchivoGrande()
        {
            const int BUFFER = -1;
            const EncryptMethod METHOD = EncryptMethod.Cesar;
            const LevelEncrypt LEVEL = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Resource.grande;
            await Cesar.EncryptDecryptPartesCommon(METHOD, LEVEL, password, dataOriginal, BUFFER);
        }
        public static async Task EncryptDecryptPartesCommon(EncryptMethod method,LevelEncrypt level,byte[] password,byte[] dataOriginal, int buffer)
        {

            byte[] dataEncrypted;
            byte[] dataDecrypted;

            Context<byte>[] contexts = DataEncrypt.Init(dataOriginal, method, true, buffer);

            await contexts.Encrypt(password, method, new StopProcess(), level);
            dataEncrypted = contexts.GetResult();
            contexts = DataEncrypt.Init(dataEncrypted, method, false, buffer);
            await contexts.Decrypt(password, method, new StopProcess(), level);
            dataDecrypted = contexts.GetResult();

            Assert.IsTrue(dataOriginal.AreEquals(dataDecrypted));
        }
    }
}
