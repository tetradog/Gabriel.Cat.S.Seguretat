using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat

{
    internal unsafe delegate int MethodCesar(Context<byte> context, byte[] password, int levelEncrypt, byte* ptrInput);
    public static class CesarMethod
    {
        const int MAX = byte.MaxValue + 1;
        public static Context<byte> InitCesar(this byte[] data, bool encryptOrDecrypt=false)
        {
            return new Context<byte>
            {
                Input = data,
                Output = new byte[data.Length]

            };
        }
        public static Context<byte> EncryptCesar(this Context<byte> context, byte[] password, LevelEncrypt level, StopProcess stopProcess)
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
            
            int preByte;
            int levelEncrypt = (int)level;
            

            unsafe
            {
                byte* ptrInput;
                byte* ptrOutput;

                fixed (byte* ptInput=context.Input,ptOutput=context.Output)
                {
                    ptrInput = ptInput + context.InputIndex;
                    ptrOutput = ptOutput + context.OutputIndex;

                    for (; !context.Acabado && stopProcess.Continue ; ptrInput++,ptrOutput++, context.InputIndex++, context.OutputIndex++)
                    {
                        preByte = method(context, password, levelEncrypt, ptrInput);

                        *ptrOutput = (byte)(preByte % MAX);

                    }
                }
            }
            return context;
        }

        private static unsafe int EncryptCesar(Context<byte> context, byte[] password, int levelEncrypt, byte* ptrInput)
        {
            return *ptrInput + SumaCesar(context, password, levelEncrypt);
        }
        private static unsafe int DecryptCesar(Context<byte> context, byte[] password, int levelEncrypt, byte* ptrInput)
        {
            int preByte = *ptrInput - SumaCesar(context, password, levelEncrypt);

            if (preByte < byte.MinValue)
            {
                preByte *= -1;
                preByte %= MAX;
                preByte *= -1;
                if (preByte < byte.MinValue)
                    preByte += MAX;

            }
            return preByte;
        }

        public static Context<byte> DecryptCesar(this Context<byte> context, byte[] password, LevelEncrypt level, StopProcess stopProcess)
        {
            Context<byte> result;
            unsafe
            {
                result = EncryptDecrypt(context, password, level, stopProcess, EncryptCesar);
            }
            return result;
        }

      
        static int SumaCesar(Context<byte> context,byte[] password, int levelEncrypt)
        {
            return password[context.InputIndex%password.Length]*levelEncrypt;
        }
    }
}
