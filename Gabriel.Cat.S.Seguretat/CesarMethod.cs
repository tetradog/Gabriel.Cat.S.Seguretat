using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat

{
    internal unsafe delegate byte MethodCesar(Context<byte> context, byte[] password, int levelEncrypt, byte* ptrInput);
    public static class CesarMethod
    {
        const int MAX = byte.MaxValue + 1;

        public static Context<byte> Encrypt(byte[] data, byte[] password, LevelEncrypt level, StopProcess stopProcess = null)
        {
            return EncryptDecrypt(data, password, true, stopProcess, level);
        }
        public static Context<byte> Decrypt(byte[] data, byte[] password, LevelEncrypt level, StopProcess stopProcess = null)
        {
            return EncryptDecrypt(data, password, false, stopProcess, level);
        }
        static Context<byte> EncryptDecrypt(byte[] data, byte[] password, bool encryptOrDecrypt = false, StopProcess stopProcess = null, LevelEncrypt level = LevelEncrypt.Normal)
        {
            Context<byte> context = new Context<byte>
            {
                Target = nameof(CesarMethod),
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
        public static Context<byte> Encrypt(Context<byte> context, byte[] password, LevelEncrypt level, StopProcess stopProcess = null)
        {
            Context<byte> result;
            unsafe
            {
                result = EncryptDecrypt(context, password, level, EncryptCesar, stopProcess);
            }
            return result;
        }
        static Context<byte> EncryptDecrypt(Context<byte> context, byte[] password, LevelEncrypt level, MethodCesar method, StopProcess stopProcess = null)
        {

            int levelEncrypt = (int)level;
            if (Equals(stopProcess, default))
            {
                stopProcess = new StopProcess();
            }
            else
            {
                stopProcess.Continue = true;
            }

            unsafe
            {

                byte* ptrOutput;

                fixed (byte* ptOutput = context.Output)
                {

                    ptrOutput = ptOutput + context.OutputIndex;

                    for (; !context.Acabado && stopProcess.Continue; ptrOutput++, context.OutputIndex++)
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
                result = EncryptDecrypt(context, password, level, DecryptCesar, stopProcess);
            }
            return result;
        }


        static int SumaCesar(Context<byte> context, byte[] password, int levelEncrypt)
        {
            return password[context.InputIndex % password.Length] * levelEncrypt;
        }
    }
}
