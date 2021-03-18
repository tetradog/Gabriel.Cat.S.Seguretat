using Gabriel.Cat.S.Extension;
using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    internal delegate long IndexPerdutMethod<T>(Context<T> data, byte[] password, int level);
    public static class PerdutMethod
    {
        public static Context<T> Encrypt<T>( T[] data, byte[] password, LevelEncrypt level, StopProcess stopProcess = null)
        {
            return EncryptDecrypt(data,password, true,  stopProcess, level);
        }
        public static Context<T> Decrypt<T>( T[] data, byte[] password, LevelEncrypt level, StopProcess stopProcess = null)
        {
            return EncryptDecrypt(data,password, false,  stopProcess, level);
        }
         static Context<T> EncryptDecrypt<T>( T[] data, byte[] password, bool encryptOrDecrypt = false, StopProcess stopProcess = null, LevelEncrypt level = LevelEncrypt.Normal)
        {
            Context<T> context= new Context<T>
            {
                Target = nameof(PerdutMethod),
                Output = data
            };
            if (encryptOrDecrypt)
            {
                Encrypt(context, password, level, stopProcess);
            }
            else
            {
                Decrypt(context, password, level, stopProcess);
            }
            return context;
        }
        public static Context<T> Encrypt<T>(Context<T> data, byte[] password, LevelEncrypt level, StopProcess stopProcess=null)
        {
            return DecryptEncrypt(data, password, stopProcess, level, IndexPerdutEncrypt);
        }
        public static Context<T> Decrypt<T>(Context<T> data, byte[] password, LevelEncrypt level, StopProcess stopProcess=null ) 
        {
            return DecryptEncrypt(data, password, stopProcess, level, IndexPerdutDecrypt);
        }
        static Context<T> DecryptEncrypt<T>(Context<T> data,byte[] password,StopProcess stopProcess,LevelEncrypt level,IndexPerdutMethod<T> metodoObtenerIndexOutput)
        {
            T aux;
            long index;
            int levelEncrypt = (int)level;


            if(Equals(stopProcess,null))
            {
                stopProcess = new StopProcess();
            }
            else
            {
                stopProcess.Continue = true;
            }

            for (; !data.Acabado && stopProcess.Continue; data.OutputIndex++)
            {
                index = metodoObtenerIndexOutput(data, password, levelEncrypt);
                aux = data.Output[index];
                data.Output[index] = data.Output[data.OutputIndex];
                data.Output[data.OutputIndex] = aux;

            }

            return data;
        }

        static long IndexPerdutEncrypt<T>(Context<T> context,byte[] password,int level) 
        {

            return (context.OutputIndex + SumaIndex(context, password, level)) % context.Output.Length;
        }
        static int SumaIndex<T>(Context<T> context,byte[] password,int level)
        {
            return password[(context.OutputIndex * level) % password.Length] * level;
        }
        static long IndexPerdutDecrypt<T>(Context<T> context, byte[] password, int level) 
        {
            return context.Output.Length-(context.OutputIndex - SumaIndex(context, password, level) % context.Output.Length);
        }

    }
}
