using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Gabriel.Cat.S.Seguretat
{
    public static class DataEncrypt
    {
        public static async Task<Context<byte>> Encrypt(this Context<byte> context, byte[] password,EncryptMethod method,StopProcess stopProcess=null,LevelEncrypt level = LevelEncrypt.Normal)
        {
            if (Equals(stopProcess, default))
            {
                stopProcess = new StopProcess();
            }
            Action encryptData = () => {
                switch (method)
                {
                    case EncryptMethod.Cesar:
                        context.CesarEncrypt(password, level, stopProcess);

                        break;
                }


            };
            await Task.Run(encryptData);
           

            return context;


        }
        public static async Task<Context<byte>> Decrypt(this Context<byte> context, byte[] password, EncryptMethod method, StopProcess stopProcess = null, LevelEncrypt level = LevelEncrypt.Normal)
        {
            if (Equals(stopProcess, default))
            {
                stopProcess = new StopProcess();
            }

            Action decryptData = () => {
                switch (method)
                {
                    case EncryptMethod.Cesar:
                        context.CesarDecrypt(password, level, stopProcess);

                        break;
                }


            };
            await Task.Run(decryptData);

            return context;


        }
    }
}
