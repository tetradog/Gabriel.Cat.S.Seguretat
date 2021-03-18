using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Gabriel.Cat.S.Seguretat.Test
{

    public abstract class Test
    {
        private EncryptMethod Method { get; set; }
        public Test(EncryptMethod method) => Method = method;
        [TestMethod]
        public async Task TestEncryptDecryptSync()
        {
            byte[] dataEncrypted;

            LevelEncrypt level = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal =Serializar.GetBytes(Resource.imagen);
            
            Context<byte> context = await DataEncrypt.Encrypt(dataOriginal, password,Method, level);
  
            dataEncrypted = context.Output;
            context = await DataEncrypt.Decrypt(dataEncrypted, password, Method, level);

            Assert.IsTrue(dataOriginal.AreEquals(context.Output));


        }
        [TestMethod]
        public async Task TestEncryptDecryptASync()
        {
            byte[] dataEncrypted;
            Task task;
            LevelEncrypt level = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Serializar.GetBytes(Resource.imagen);
            StopProcess stopProcess = new StopProcess() { Continue = false };
            Context<byte> context = await DataEncrypt.Encrypt(dataOriginal, password, Method, level,stopProcess);
            Action act = async () =>
            {
                while(!context.Acabado)
                    await DataEncrypt.Encrypt(dataOriginal, password, Method, level, stopProcess);
            };
            stopProcess.Continue = true;
            task = Task.Run(act);

            task.Wait(150);
            stopProcess.Continue = false;
            task.Wait(1500);
            stopProcess.Continue = true;
            await task;
          
            dataEncrypted = context.Output;
            context = await DataEncrypt.Decrypt(dataEncrypted, password, Method, level);

            Assert.IsTrue(dataOriginal.AreEquals(context.Output));


        }
        [TestMethod]
        public async Task TestCesarEncryptDecryptASyncPartes()
        {
            const int BUFFER = 1024 * 512;

            const LevelEncrypt LEVEL = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Serializar.GetBytes(Resource.imagen);
            await EncryptDecryptPartesCommon(LEVEL, password, dataOriginal, BUFFER);
        }
        [TestMethod]
        public async Task TestCesarEncryptDecryptASyncParte()
        {
            const int BUFFER = -1;

            const LevelEncrypt LEVEL = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Serializar.GetBytes(Resource.imagen);
            await EncryptDecryptPartesCommon( LEVEL, password, dataOriginal, BUFFER);
        }
        [TestMethod]
        public async Task TestPerdutEncryptDecryptASyncPartesArchivoGrande()
        {
            const int BUFFER = 1024 * 512;
            const LevelEncrypt LEVEL = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal =Resource.grande;
            await EncryptDecryptPartesCommon(LEVEL, password, dataOriginal, BUFFER);
        }
        [TestMethod]
        public async Task TestPerdutEncryptDecryptASyncParteArchivoGrande()
        {
            const int BUFFER = -1;

            const LevelEncrypt LEVEL = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Resource.grande;
            await EncryptDecryptPartesCommon( LEVEL, password, dataOriginal, BUFFER);
        }
        public  async Task EncryptDecryptPartesCommon(LevelEncrypt level,byte[] password,byte[] dataOriginal, int buffer)
        {

            byte[] dataEncrypted;
            byte[] dataDecrypted;

            Context<byte>[] contexts  = await DataEncrypt.Encrypt(dataOriginal,password,Method,buffer,level);

            dataEncrypted = contexts.GetResult();
            contexts = await DataEncrypt.Decrypt(dataEncrypted, password, Method, buffer, level);
            dataDecrypted = contexts.GetResult();

            Assert.IsTrue(dataOriginal.AreEquals(dataDecrypted));
        }
    }
}
