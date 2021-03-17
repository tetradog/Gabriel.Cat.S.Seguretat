using Gabriel.Cat.S.Extension;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Gabriel.Cat.S.Seguretat
{
    public static class DataEncrypt
    {
        public static Context<byte>[] Init(this byte[] data,EncryptMethod method,bool encryptOrDecrypt=true, int buffer = -1)
        {
            if(buffer<=0)
            {
                buffer = data.Length;
            }

            Context<byte>[] contexts;
            byte[] aux;
            Context<byte> context=null;
            int total = data.Length / buffer;

            if (data.Length % buffer != 0)
            {
                total++;
            }
            contexts= new Context<byte>[total];

            for(int i = 0; i < contexts.Length; i++)
            {
                aux = data.SubArray(i * buffer, buffer);
                switch (method)
                {
                    case EncryptMethod.Cesar:
                        context = aux.InitCesar(encryptOrDecrypt);
                        break;
                    case EncryptMethod.Perdut:
                        context = aux.InitPerdut(encryptOrDecrypt);
                        break;
                }
                contexts[i] = context;
                
            }


            return contexts;

        }
        public static byte[] GetResult(this IList<Context<byte>> contexts)
        {
            return new byte[0].AddArray(contexts.Convert((i) => i.Output));
        }
        public static async Task<IList<Context<byte>>> Encrypt(this IList<Context<byte>> contexts, byte[] password, EncryptMethod method, StopProcess stopProcess = null, LevelEncrypt level = LevelEncrypt.Normal) 
        {
            if (Equals(stopProcess, default))
            {
                stopProcess = new StopProcess();
            }

            Task[] tasks = new Task[contexts.Count];
            for(int i = 0; i < contexts.Count; i++)
            {
                tasks[i] = contexts[i].Encrypt(password, method, stopProcess, level);
            }

            await Task.WhenAll(tasks);
            return contexts;
        }
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
                        CesarMethod.Encrypt(context,password, level, stopProcess);

                        break;
                    case EncryptMethod.Perdut:
                        PerdutMethod.Encrypt(context,password, level, stopProcess);

                        break;
                }


            };
            await Task.Run(encryptData);
           

            return context;


        }
        public static async Task<IList<Context<byte>>> Decrypt(this IList<Context<byte>> contexts, byte[] password, EncryptMethod method, StopProcess stopProcess = null, LevelEncrypt level = LevelEncrypt.Normal)
        {
            if (Equals(stopProcess, default))
            {
                stopProcess = new StopProcess();
            }

            Task[] tasks = new Task[contexts.Count];
            for (int i = 0; i < contexts.Count; i++)
            {
                tasks[i] = contexts[i].Decrypt(password, method, stopProcess, level);
            }

            await Task.WhenAll(tasks);
            return contexts;
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
                        CesarMethod.Decrypt(context,password, level, stopProcess);

                        break;
                    case EncryptMethod.Perdut:
                        PerdutMethod.Decrypt(context,password, level, stopProcess);

                        break;
                }


            };
            await Task.Run(decryptData);

            return context;


        }
    }
}
