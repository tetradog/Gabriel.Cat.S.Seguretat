using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    public static class Disimulat
    {
        public static int LenghtEncrtypt(int lengthDecrypt,byte[] password, LevelEncrypt level,Ordre order)
        {
            int longitudArray = lengthDecrypt;
            int pos = 0;
            for (int i = 0, f = lengthDecrypt; i <= f; i++)
            {
                longitudArray += EncryptDecrypt.CalculoNumeroCifrado(password, level, order, pos);
         
                pos += 2;
            }
            return longitudArray;
        }
        public static int LenghtDecrypt(int lenghtEncrypt, byte[] password, LevelEncrypt level, Ordre order)
        {
            int longitudAux = lenghtEncrypt;
            int longitud = 0;
            int pos = 0;
            //calculo la longitud original
            while (longitudAux > 0)
            {
                //le resto los caracteres random
                longitudAux -= EncryptDecrypt.CalculoNumeroCifrado(password, level, order, pos);
                //quito el caracter original
                longitudAux--;
                //lo cuento
                longitud++;
                pos += 2;
            }
            longitud--;
            return longitud;
        }

        public static byte[] Encrypt(byte[] data,byte[] password,LevelEncrypt level,Ordre ordre)
        {
            Context<byte> context = new Context<byte>();
            context.DataIn = data;
            context.DataOut = new byte[LenghtEncrtypt(context.DataIn.Length, password, level, ordre)];
            Encrypt(context, password, level, ordre);
            return context.DataOut;
        }
        public static Context<byte> Encrypt(Context<byte> context, byte[] password, LevelEncrypt level, Ordre order)
        {

            int numBytesRandom;
            unsafe
            {
                byte* ptrBytesDisimulats, ptrBytes;
                context.DataOut.UnsafeMethod((unsBytesDisimulats) => context.DataIn.UnsafeMethod(unsBytes => {
                    ptrBytesDisimulats = unsBytesDisimulats.PtrArray+context.InitDataOut;
                    ptrBytes = unsBytes.PtrArray+context.InitDataIn;
                    for (; context.ForI < context.ForF&&context.Continua; context.ForI++)
                    {
                        //recorro la array de bytes y pongo los bytes nuevos que tocan
                        numBytesRandom =EncryptDecrypt.CalculoNumeroCifrado(password, level, order, context.Pos);
                        for (int j = 0; j < numBytesRandom; j++)
                        {
                            *ptrBytesDisimulats = (byte)MiRandom.Next(byte.MaxValue + 1);
                            ptrBytesDisimulats++;
                        }
                        *ptrBytesDisimulats = *ptrBytes;
                        ptrBytesDisimulats++;
                        ptrBytes++;
                        context.Pos += 2;
                    }
                    if (context.Continua)
                    {
                        //para disumular el ultimo!
                        numBytesRandom = EncryptDecrypt.CalculoNumeroCifrado(password, level, order, context.Pos);
                        for (int j = 0; j < numBytesRandom; j++)
                        {
                            *ptrBytesDisimulats = (byte)MiRandom.Next(byte.MaxValue + 1);
                            ptrBytesDisimulats++;
                        }
                    }
                }));
            }
            return context;


        }

        public static byte[] Decrypt(byte[] data, byte[] password, LevelEncrypt level, Ordre ordre)
        {
            Context<byte> context = new Context<byte>();
            context.DataIn = data;
            context.DataOut = new byte[LenghtDecrypt(context.DataIn.Length, password, level, ordre)];
            Decrypt(context, password, level, ordre);
            return context.DataOut;
        }
        public static Context<byte>  Decrypt(Context<byte> context, byte[] password, LevelEncrypt level, Ordre order)
        {
              unsafe
            {
                byte* ptrBytes, ptrBytesTrobats;
                context.DataOut.UnsafeMethod((unsBytesTrobats) => context.DataIn.UnsafeMethod(unsBytes => {
                    ptrBytesTrobats = unsBytesTrobats.PtrArray+context.InitDataOut;
                    ptrBytes = unsBytes.PtrArray+context.InitDataIn;
                    for (; context.ForI < context.ForF; context.ForI++)
                    {
                        //recorro la array de bytes y pongo los bytes nuevos que tocan
                        ptrBytes += EncryptDecrypt.CalculoNumeroCifrado(password, level, order, context.Pos);
                        //me salto los bytes random
                        *ptrBytesTrobats = *ptrBytes;
                        //pongo el byte original
                        ptrBytesTrobats++;
                        //avanzo
                        ptrBytes++;
                        context.Pos += 2;
                    }
                }));
            }
            return context;
        }
    }
}
