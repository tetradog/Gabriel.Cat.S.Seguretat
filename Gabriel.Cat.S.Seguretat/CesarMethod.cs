using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    public static class CesarMethod
    {
        const int MAX = byte.MaxValue + 1;
        public static Context<byte> CesarInit(this byte[] data)
        {
            return new Context<byte>
            {
                Input = data,
                Output = new byte[data.Length]

            };
        }
        public static Context<byte> CesarEncrypt(this Context<byte> context,byte[] password,LevelEncrypt level,StopProcess stopProcess)
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
                        preByte = *ptrInput + SumaCesar(context,password, levelEncrypt);
                       
                        *ptrOutput = (byte)(preByte% MAX);

                    }
                }
            }
            return context;
        }
        public static Context<byte> CesarDecrypt(this Context<byte> context, byte[] password, LevelEncrypt level, StopProcess stopProcess)
        {
            int preByte;
            int levelEncrypt = (int)level;

            unsafe
            {
                byte* ptrInput;
                byte* ptrOutput;

                fixed (byte* ptInput = context.Input, ptOutput = context.Output)
                {
                    ptrInput = ptInput + context.InputIndex;
                    ptrOutput = ptOutput + context.OutputIndex;

                    for (; !context.Acabado && stopProcess.Continue; ptrInput++, ptrOutput++, context.InputIndex++, context.OutputIndex++)
                    {
                        preByte = *ptrInput - SumaCesar(context, password, levelEncrypt);

                        if (preByte < byte.MinValue)
                        {
                            preByte *= -1;
                            preByte %= MAX;
                            preByte *= -1;
                            if (preByte < byte.MinValue)
                                preByte += MAX;

                        }

                        *ptrOutput = (byte)(preByte);

                    }
                }
            }
            return context;
        }
        static int SumaCesar(Context<byte> context,byte[] password, int levelEncrypt)
        {
            return password[context.InputIndex%password.Length]*levelEncrypt;
        }
    }
}
