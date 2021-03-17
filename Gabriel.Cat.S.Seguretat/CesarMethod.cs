using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat

{
    internal unsafe delegate byte MethodCesar(Context<byte> context, byte[] password, int levelEncrypt, byte* ptrInput);
    public static class CesarMethod
    {
        const int MAX = byte.MaxValue + 1;
        public static Context<byte> InitCesar(this byte[] data, bool encryptOrDecrypt=false)
        {
            return new Context<byte>
            {
                Target=nameof(CesarMethod),
                Output = data

            };
        }
        public static Context<byte> Encrypt(Context<byte> context, byte[] password, LevelEncrypt level, StopProcess stopProcess)
        {
            Context<byte> result;
            unsafe 
            { 
                result = EncryptDecrypt(context, password, level, stopProcess, EncryptCesar); 
            }
            return result;
        }
             static Context<byte> EncryptDecrypt( Context<byte> context,byte[] password,LevelEncrypt level,StopProcess stopProcess,MethodCesar method)
        {
            
            int levelEncrypt = (int)level;
            

            unsafe
            {

                byte* ptrOutput;

                fixed (byte* ptOutput=context.Output)
                {

                    ptrOutput = ptOutput + context.OutputIndex;

                    for (; !context.Acabado && stopProcess.Continue ;ptrOutput++, context.OutputIndex++)
                    {
    

                        *ptrOutput = method(context, password, levelEncrypt, ptrOutput);

                    }
                }
            }
            return context;
        }

        private static unsafe byte EncryptCesar(Context<byte> context, byte[] password, int levelEncrypt, byte* ptrOutput)
        {
            int preByte = *ptrOutput + SumaCesar(context, password, levelEncrypt);
            if (preByte > MAX)
            {
                preByte %= MAX;
            }
            return (byte)preByte;
        }
        private static unsafe byte DecryptCesar(Context<byte> context, byte[] password, int levelEncrypt, byte* ptrOutput)
        {
            int preByte = *ptrOutput - SumaCesar(context, password, levelEncrypt);

            if (preByte < byte.MinValue)
            {
                preByte *= -1;
                preByte %= MAX;
                preByte *= -1;
                preByte += MAX;

            }
            return (byte)preByte;
        }

        public static Context<byte> Decrypt(Context<byte> context, byte[] password, LevelEncrypt level, StopProcess stopProcess)
        {
            Context<byte> result;
            unsafe
            {
                result = EncryptDecrypt(context, password, level, stopProcess, DecryptCesar);
            }
            return result;
        }

      
        static int SumaCesar(Context<byte> context,byte[] password, int levelEncrypt)
        {
            return password[context.InputIndex%password.Length]*levelEncrypt;
        }
    }
}
