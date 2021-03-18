using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    internal static class CommonDisimulatMethod
    {
        internal static Context<byte> Encrypt(byte[] data, byte[] password, int min, int max, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            Context<byte> context = new Context<byte>
            {

                Input = data,
                Output = new byte[GetLengthEncrypted(data.Length, password, level)]

            };
            Encrypt(context, password,min,max, level, stopProcess);
            return context;
        }
        internal static Context<byte> Encrypt(Context<byte> context, byte[] password, int min, int max, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {

            if (Equals(stopProcess, null))
            {
                stopProcess = new StopProcess();
            }
            else
            {
                stopProcess.Continue = true;
            }

            int randomTrush;
            int levelEncrypt = (int)level;

            for (; !context.Acabado && stopProcess.Continue; context.InputIndex++)
            {
                //pongo random
                randomTrush = password[context.InputIndex % password.Length] * levelEncrypt;
                for (int i = 0; i < randomTrush; i++)
                {
                    context.Output[context.OutputIndex] = (byte)MiRandom.Next(min, max);
                    context.OutputIndex++;
                }
                //pongo data
                context.Output[context.OutputIndex] = context.Input[context.InputIndex];
                context.OutputIndex++;

            }

            return context;
        }
        internal static Context<byte> Decrypt(byte[] data, byte[] password, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            Context<byte> context = new Context<byte>
            {

                Input = data,
                Output = new byte[GetLengthDecrypted(data.Length, password, level)]

            };
            Decrypt(context, password, level, stopProcess);
            return context;
        }
        internal static Context<byte> Decrypt(Context<byte> context, byte[] password, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {

            if (Equals(stopProcess, null))
            {
                stopProcess = new StopProcess();
            }
            else
            {
                stopProcess.Continue = true;
            }
            int randomTrush;
            int levelEncrypt = (int)level;

            for (; !context.Acabado && stopProcess.Continue; context.OutputIndex++)
            {
                //quito random
                randomTrush = password[context.OutputIndex % password.Length] * levelEncrypt;
                context.InputIndex += randomTrush;
                //pongo data
                context.Output[context.OutputIndex] = context.Input[context.InputIndex];

            }
            return context;
        }
        internal static int GetLengthEncrypted(int lengthOriginal, byte[] password, LevelEncrypt level)
        {
            int levelEncrypt = (int)level;
            int longitudArray = lengthOriginal;
            int pos = 0;
            for (int i = 0, f = lengthOriginal; i <= f; i++)
            {
                longitudArray += password[pos % password.Length] * levelEncrypt;

                pos += 2;
            }
            return longitudArray;

        }
        internal static int GetLengthDecrypted(int lengthOriginal, byte[] password, LevelEncrypt level)
        {
            int longitudAux = lengthOriginal;
            int levelEncrypt = (int)level;
            int longitud = 0;
            int pos = 0;
            //calculo la longitud original
            while (longitudAux > 0)
            {
                //le resto los caracteres random
                longitudAux -= password[pos % password.Length] * levelEncrypt;
                //quito el caracter original
                longitudAux--;
                //lo cuento
                longitud++;
                pos += 2;
            }
            longitud--;
            return longitud;
        }
    }
    public static class DisimulatRandomMethod
    {
        const int MAX = byte.MaxValue + 1;

        public static Context<byte> Encrypt(byte[] data, byte[] password, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            return CommonDisimulatMethod.Encrypt(data, password, 0, MAX,level,stopProcess);
        }
        public static Context<byte> Encrypt(Context<byte> context, byte[] password, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            
            return CommonDisimulatMethod.Encrypt(context, password,0,MAX, level, stopProcess);
        }

        public static Context<byte> Decrypt( byte[] data, byte[] password, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            return CommonDisimulatMethod.Decrypt(data, password, level, stopProcess);
        }
        public static Context<byte> Decrypt(Context<byte> context, byte[] password, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            return CommonDisimulatMethod.Decrypt(context, password, level, stopProcess);
        }
        public static int GetLengthEncrypted(int lengthOriginal,byte[] password,LevelEncrypt level)
        {
            return CommonDisimulatMethod.GetLengthEncrypted(lengthOriginal, password, level);
        }
        public static int GetLengthDecrypted(int lengthOriginal,byte[] password,LevelEncrypt level)
        {
            return CommonDisimulatMethod.GetLengthDecrypted(lengthOriginal, password, level);
        }
    }
    public static class DisimulatMethod
    {
        

        public static Context<byte> Encrypt(byte[] data, byte[] password, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            TwoKeys<int, int> minMax = GetMinMax(data);
            return CommonDisimulatMethod.Encrypt(data, password, minMax.Key1, minMax.Key2, level, stopProcess);
        }
        public static Context<byte> Encrypt(Context<byte> context, byte[] password, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            TwoKeys<int, int> minMax = GetMinMax(context.Input);
            return CommonDisimulatMethod.Encrypt(context, password, minMax.Key1, minMax.Key2, level, stopProcess);
        }

        private static TwoKeys<int, int> GetMinMax(byte[] data)
        {
            const int MAX = byte.MaxValue + 1;
            int min = MAX;
            int max = 0;
            unsafe
            {
                byte* ptrData;
                fixed(byte* ptData = data)
                {
                    ptrData = ptData;
                    for(int i=0;i<data.Length;i++)
                    {
                        if (*ptrData < min)
                            min = *ptrData;
                        if (*ptrData > max)
                            max = *ptrData;
                    }

                }
            }
            return new TwoKeys<int, int>(min,max);
        }

        public static Context<byte> Decrypt(byte[] data, byte[] password, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            return CommonDisimulatMethod.Decrypt(data, password, level, stopProcess);
        }
        public static Context<byte> Decrypt(Context<byte> context, byte[] password, LevelEncrypt level = LevelEncrypt.Normal, StopProcess stopProcess = null)
        {
            return CommonDisimulatMethod.Decrypt(context, password, level, stopProcess);
        }
        public static int GetLengthEncrypted(int lengthOriginal, byte[] password, LevelEncrypt level)
        {
            return CommonDisimulatMethod.GetLengthEncrypted(lengthOriginal, password, level);
        }
        public static int GetLengthDecrypted(int lengthOriginal, byte[] password, LevelEncrypt level)
        {
            return CommonDisimulatMethod.GetLengthDecrypted(lengthOriginal, password, level);
        }
    }
}
