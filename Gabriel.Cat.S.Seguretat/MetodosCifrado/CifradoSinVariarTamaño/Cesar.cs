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
        public static int LenghtEncrtypt(int lengthDecrypt, byte[] password, LevelEncrypt level, Ordre order)
        {
            return lengthDecrypt;
        }
        public static int LenghtDecrypt(int lenghtEncrypt, byte[] password, LevelEncrypt level, Ordre order)
        {
            return lenghtEncrypt;
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
