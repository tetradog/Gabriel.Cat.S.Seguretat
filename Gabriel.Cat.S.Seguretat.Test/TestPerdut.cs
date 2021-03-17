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
    public class Perdut
    {
        [TestMethod]
        public void TestPerdutEncryptDecryptSync()
        {
            byte[] dataEncrypted;

            LevelEncrypt level = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal =Serializar.GetBytes(Resource.imagen);
            
            Context<byte> context = PerdutMethod.InitPerdut(dataOriginal);
            PerdutMethod.Encrypt(context,password, level, new StopProcess());
            dataEncrypted = context.Output;
            context = PerdutMethod.InitPerdut(dataEncrypted);
            PerdutMethod.Decrypt(context,password,level,new StopProcess());
            Assert.IsTrue(dataOriginal.AreEquals(context.Output));


        }
        [TestMethod]
        public async Task TestPerdutEncryptDecryptASync()
        {
            byte[] dataEncrypted;

            LevelEncrypt level = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Serializar.GetBytes(Resource.imagen);
            StopProcess stopProcess = new StopProcess();
            Context<byte> context = PerdutMethod.InitPerdut(dataOriginal);
            Action act = () =>
            {
                while(!context.Acabado)
                    PerdutMethod.Encrypt(context, password, level, stopProcess);
            };
            Task task = Task.Run(act);

            task.Wait(150);
            stopProcess.Continue = false;
            task.Wait(1500);
            stopProcess.Continue = true;
            await task;
          
            dataEncrypted = context.Output;
            context = PerdutMethod.InitPerdut(dataEncrypted);
            PerdutMethod.Decrypt(context, password, level, stopProcess);
            Assert.IsTrue(dataOriginal.AreEquals(context.Output));


        }
        [TestMethod]
        public async Task TestPerdutEncryptDecryptASyncPartes()
        {
            byte[] dataEncrypted;
            byte[] dataDecrypted;
            LevelEncrypt level = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Serializar.GetBytes(Resource.imagen);
            Context<byte>[] contexts = DataEncrypt.Init(dataOriginal, EncryptMethod.Perdut, true, 3024);
            await contexts.Encrypt(password, EncryptMethod.Perdut, new StopProcess(), level);
            dataEncrypted = contexts.GetResult();
            contexts = DataEncrypt.Init(dataEncrypted, EncryptMethod.Perdut, false, 3024);
            await contexts.Decrypt(password, EncryptMethod.Perdut, new StopProcess(), level);
            dataDecrypted = contexts.GetResult();

            Assert.IsTrue(dataOriginal.AreEquals(dataDecrypted));
        }

        }
}
