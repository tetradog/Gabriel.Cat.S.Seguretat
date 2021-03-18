using Gabriel.Cat.S.Extension;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Gabriel.Cat.S.Seguretat
{
    public static class DataEncrypt
    {
        public static async Task<Context<byte>[]> Encrypt(byte[] data, byte[] password, EncryptMethod method, int buffer, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            return await EncryptDecrypt(data, password, stopProcess, method, level, true, buffer);
        }
        public static async Task<Context<byte>[]> Decrypt(byte[] data, byte[] password, EncryptMethod method, int buffer, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            return await EncryptDecrypt(data, password, stopProcess, method, level, false, buffer);
        }
         static async Task<Context<byte>[]> EncryptDecrypt(byte[] data,byte[] password, StopProcess stopProcess, EncryptMethod method,LevelEncrypt level,bool encryptOrDecrypt, int buffer = -1)
        {
            if(buffer<=0)
            {
                buffer = data.Length;
            }

            Task < Context<byte>>[] contexts;
            byte[] aux;
             
            int total = data.Length / buffer;

            if (data.Length % buffer != 0)
            {
                total++;
            }
            contexts= new Task<Context<byte>>[total];

            for(int i = 0; i < contexts.Length; i++)
            {
                aux = data.SubArray(i * buffer, buffer);
                if (encryptOrDecrypt)
                {
                    contexts[i] = Encrypt(aux, password, method, stopProcess, level);
                }
                else
                {
                    contexts[i] = Decrypt(aux, password, method, stopProcess, level);
                }
                
            }
            await Task.WhenAll(contexts);



            return contexts.Convert((c)=>c.Result);

        }
        public static byte[] GetResult(this IList<Context<byte>> contexts)
        {

            byte[] result;
            if (contexts.Count > 1)
            {
                result = new byte[0].AddArray(contexts.Convert((i) => i.Output));
            }
            else
            {
                result = contexts[0].Output;
            }
            return result;
        }
        public static async Task<IList<Context<byte>>> Encrypt(this IList<Context<byte>> contexts, byte[] password, EncryptMethod method, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null) 
        {
            if (Equals(stopProcess, default))
            {
                stopProcess = new StopProcess();
            }
            else
            {
                stopProcess.Continue = true;
            }

            Task[] tasks = new Task[contexts.Count];
            for(int i = 0; i < contexts.Count; i++)
            {
                tasks[i] = Encrypt(contexts[i],password, method, stopProcess, level);
            }

            await Task.WhenAll(tasks);
            return contexts;
        }
        public static async Task<Context<byte>> Encrypt(byte[] data, byte[] password, EncryptMethod method, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            if (Equals(stopProcess, default))
            {
                stopProcess = new StopProcess();
            }
            else
            {
                stopProcess.Continue = true;
            }

            Context<byte> context = default;

            Action decryptData = () => {
                switch (method)
                {
                    case EncryptMethod.Cesar:
                        context = CesarMethod.Encrypt(data, password, level, stopProcess);

                        break;
                    case EncryptMethod.Perdut:
                        context = PerdutMethod.Encrypt(data, password, level, stopProcess);

                        break;
                    case EncryptMethod.Disimulat:
                        context = DisimulatMethod.Encrypt(data, password, level, stopProcess);

                        break;
                    case EncryptMethod.DisimulatRandom:
                        context = DisimulatRandomMethod.Encrypt(data, password, level, stopProcess);

                        break;
                }


            };
            await Task.Run(decryptData);

            return context;


        }
        public static async Task<Context<byte>> Encrypt( Context<byte> context, byte[] password,EncryptMethod method, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess=null)
        {
            if (Equals(stopProcess, default))
            {
                stopProcess = new StopProcess();
            }
            else
            {
                stopProcess.Continue = true;
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
                    case EncryptMethod.Disimulat:
                        DisimulatMethod.Encrypt(context, password, level, stopProcess);

                        break;
                    case EncryptMethod.DisimulatRandom:
                        DisimulatRandomMethod.Encrypt(context, password, level, stopProcess);

                        break;
                }


            };
            await Task.Run(encryptData);
           

            return context;


        }
        public static async Task<IList<Context<byte>>> Decrypt(this IList<Context<byte>> contexts, byte[] password, EncryptMethod method, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            if (Equals(stopProcess, default))
            {
                stopProcess = new StopProcess();
            }
            else
            {
                stopProcess.Continue = true;
            }

            Task[] tasks = new Task[contexts.Count];
            for (int i = 0; i < contexts.Count; i++)
            {
                tasks[i] = Decrypt(contexts[i],password, method, stopProcess, level);
            }

            await Task.WhenAll(tasks);
            return contexts;
        }
        public static async Task<Context<byte>> Decrypt(byte[] data, byte[] password, EncryptMethod method, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            if (Equals(stopProcess, default))
            {
                stopProcess = new StopProcess();
            }
            else
            {
                stopProcess.Continue = true;
            }
            Context<byte> context=default;
            Action decryptData = () => {
                switch (method)
                {
                    case EncryptMethod.Cesar:
                        context= CesarMethod.Decrypt(data, password, level, stopProcess);

                        break;
                    case EncryptMethod.Perdut:
                        context = PerdutMethod.Decrypt(data, password, level, stopProcess);

                        break;
                    case EncryptMethod.Disimulat:
                        context = DisimulatMethod.Decrypt(data, password, level, stopProcess);

                        break;
                    case EncryptMethod.DisimulatRandom:
                        context = DisimulatRandomMethod.Decrypt(data, password, level, stopProcess);

                        break;
                }


            };
            await Task.Run(decryptData);

            return context;


        }

        public static async Task<Context<byte>> Decrypt( Context<byte> context, byte[] password, EncryptMethod method, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            if (Equals(stopProcess, default))
            {
                stopProcess = new StopProcess();
            }
            else
            {
                stopProcess.Continue = true;
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
                    case EncryptMethod.Disimulat:
                        DisimulatMethod.Decrypt(context, password, level, stopProcess);

                        break;
                    case EncryptMethod.DisimulatRandom:
                        DisimulatRandomMethod.Decrypt(context, password, level, stopProcess);

                        break;
                }


            };
            await Task.Run(decryptData);

            return context;


        }
    }
}
