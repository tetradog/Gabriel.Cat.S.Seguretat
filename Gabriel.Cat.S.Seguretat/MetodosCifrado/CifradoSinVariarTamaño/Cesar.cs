using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
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
        public static byte[] Encrypt(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
        {
            byte[] bytesEncryptats = new byte[bytes.Length];
            int sumaCesar;
            unsafe
            {
                byte* ptrBytesOri, ptrBytesCesarEncrypt;
                bytesEncryptats.UnsafeMethod((unsByteEncriptat) => bytes.UnsafeMethod(unsBytes => {
                    ptrBytesOri = unsBytes.PtrArray;
                    ptrBytesCesarEncrypt = unsByteEncriptat.PtrArray;
                    for (long i = 0, pos = 0; i < unsBytes.Length; i++, pos += 2)
                    {
                        sumaCesar = EncryptDecrypt.CalculoNumeroCifrado(password, level, order, pos);
                        *ptrBytesCesarEncrypt = (byte)((*ptrBytesOri + sumaCesar) % (byte.MaxValue + 1));
                        ptrBytesCesarEncrypt++;
                        ptrBytesOri++;
                    }
                }));
            }
            return bytesEncryptats;
        }
        public static byte[] Decrypt(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
        {
            byte[] bytesDesencryptats = new byte[bytes.Length];
            int restaCesar;
            int preByte;
            unsafe
            {
                byte* ptrBytesCesarEcnrypt, ptrBytesCesarDecrypt;
                bytesDesencryptats.UnsafeMethod((unsByteDesencryptat) => bytes.UnsafeMethod(unsBytes => {
                    ptrBytesCesarEcnrypt = unsBytes.PtrArray;
                    ptrBytesCesarDecrypt = unsByteDesencryptat.PtrArray;
                    for (long i = 0, pos = 0; i < unsBytes.Length; i++, pos += 2)
                    {
                        restaCesar = EncryptDecrypt.CalculoNumeroCifrado(password, level, order, pos);
                        preByte = *ptrBytesCesarEcnrypt - restaCesar;

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
                        ptrBytesCesarEcnrypt++;
                    }
                }));
            }
            return bytesDesencryptats;
        }
    }
}
