using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
   public static class Cesar
    {
        public static int LenghtEncrtypt(int lengthDecrypt, byte[] password = default, LevelEncrypt level = default, Ordre order = default)
        {
            return lengthDecrypt;
        }
        public static int LenghtDecrypt(int lenghtEncrypt, byte[] password = default, LevelEncrypt level = default, Ordre order = default)
        {
            return lenghtEncrypt;
        }
        public static Context<byte> InitContextEncrypt(byte[] data, byte[] password = default, LevelEncrypt level = default, Ordre order=default)
        {
            Context<byte> context = new Context<byte>();
            context.DataIn = data;
            context.DataOut = new byte[data.Length];
            context.ForF = data.Length;
            context.ForI = 0;

            return context;
        }
        public static Context<byte> InitContextDecrypt(byte[] data, byte[] password, LevelEncrypt level, Ordre order)
        {
            return InitContextEncrypt(data, password, level, order);
        }
        public static byte[] Encrypt(byte[] data, byte[] password, LevelEncrypt level, Ordre order)
        {
            return Encrypt(InitContextEncrypt(data, password, level, order), password, level, order).DataOut;
        }
        public static Context<byte> Encrypt(Context<byte> context, byte[] password, LevelEncrypt level, Ordre order)
        {
            int sumaCesar;
            unsafe
            {
                byte* ptrBytesOri, ptrBytesCesarEncrypt;
                context.DataOut.UnsafeMethod((unsByteEncriptat) => context.DataOut.UnsafeMethod(unsBytes => {
                    ptrBytesOri = unsBytes.PtrArray+context.ForI;
                    ptrBytesCesarEncrypt = unsByteEncriptat.PtrArray + context.ForI;
                    for (; context.ForI < context.DataOut.Length&&context.Continua; context.ForI++, context.Pos += 2)
                    {
                        sumaCesar = EncryptDecrypt.CalculoNumeroCifrado(password, level, order, context.Pos);
                        *ptrBytesCesarEncrypt = (byte)((*ptrBytesOri + sumaCesar) % (byte.MaxValue + 1));
                        ptrBytesCesarEncrypt++;
                        ptrBytesOri++;
                    }
                }));
            }
            return context;
        }
        public static byte[] Decrypt(byte[] data, byte[] password, LevelEncrypt level, Ordre order)
        {
            return Decrypt(InitContextDecrypt(data, password, level, order), password, level, order).DataOut;
        }
        public static Context<byte> Decrypt(Context<byte> context, byte[] password, LevelEncrypt level, Ordre order)
        {
            int restaCesar;
            int preByte;
            unsafe
            {
                byte*  ptrBytesCesarDecrypt;
                context.DataOut.UnsafeMethod((unsByteDesencryptat) =>
                {

                    ptrBytesCesarDecrypt = unsByteDesencryptat.PtrArray+context.ForI;

                    for (; context.ForI < context.DataOut.Length&&context.Continua; context.ForI++, context.Pos += 2)
                    {
                        restaCesar = EncryptDecrypt.CalculoNumeroCifrado(password, level, order, context.Pos);
                        preByte = *ptrBytesCesarDecrypt - restaCesar;

                        if (preByte < byte.MinValue)
                        {
                            preByte *= -1;
                            preByte %= (byte.MaxValue + 1);
                            preByte *= -1;
                            if (preByte < byte.MinValue)
                                preByte += byte.MaxValue + 1;

                        }

                        //tengo lo que le han puesto de mas y tengo que quitarselo teniendo en cuenta que cuando llegue a 0 tiene que seguir 255
                        *ptrBytesCesarDecrypt = (byte)preByte;
                        ptrBytesCesarDecrypt++;
                    }
                } );
            }
            return context;
        }
    }
}
