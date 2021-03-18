﻿using Gabriel.Cat.S.Extension;
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
            
            Context<byte> context = CesarMethod.Encrypt(dataOriginal, password, level);
  
            dataEncrypted = context.Output;
            context = CesarMethod.Decrypt(dataEncrypted, password, level);

            Assert.IsTrue(dataOriginal.AreEquals(context.Output));


        }
        [TestMethod]
        public async Task TestCesarEncryptDecryptASync()
        {
            byte[] dataEncrypted;
            Task task;
            LevelEncrypt level = LevelEncrypt.Normal;
            byte[] password = Serializar.GetBytes("password");
            byte[] dataOriginal = Serializar.GetBytes(Resource.imagen);
            StopProcess stopProcess = new StopProcess() { Continue = false };
            Context<byte> context = CesarMethod.Encrypt(dataOriginal, password, level, stopProcess);
            Action act = () =>
            {
                while(!context.Acabado)
                  CesarMethod.Encrypt(context, password, level, stopProcess);
            };
            stopProcess.Continue = true;
            task = Task.Run(act);

            task.Wait(150);
            stopProcess.Continue = false;
            task.Wait(1500);
            stopProcess.Continue = true;
            await task;
          
            dataEncrypted = context.Output;
            context = CesarMethod.Decrypt(dataEncrypted, password, level, stopProcess);

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

            Context<byte>[] contexts  = await DataEncrypt.Encrypt(dataOriginal,password,method,buffer,null,level);

            dataEncrypted = contexts.GetResult();
            contexts = await DataEncrypt.Decrypt(dataEncrypted, password, method, buffer, null, level);
            dataDecrypted = contexts.GetResult();

            Assert.IsTrue(dataOriginal.AreEquals(dataDecrypted));
        }
    }
}
