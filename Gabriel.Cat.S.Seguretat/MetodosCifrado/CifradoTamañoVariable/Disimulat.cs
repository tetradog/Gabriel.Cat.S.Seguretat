using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    public static class Disimulat
    {
        public static byte[] Encrypt(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
        {//por testear la ultima cosa :D
            byte[] bytesDisimulats;
            long longitudArray = bytes.Length;
            int numBytesRandom;
            long pos = 0;
            //calculo la longitud final
            for (long i = 0, f = longitudArray; i <= f; i++)
            {
                longitudArray += EncryptDecrypt.CalculoNumeroCifrado(password, level, order, pos);
                pos += 2;
            }
            bytesDisimulats = new byte[longitudArray];
            pos = 0;
            unsafe
            {
                byte* ptrBytesDisimulats, ptrBytes;
                bytesDisimulats.UnsafeMethod((unsBytesDisimulats) => bytes.UnsafeMethod(unsBytes => {
                    ptrBytesDisimulats = unsBytesDisimulats.PtrArray;
                    ptrBytes = unsBytes.PtrArray;
                    for (long i = 0, f = bytes.Length; i < f; i++)
                    {
                        //recorro la array de bytes y pongo los bytes nuevos que tocan
                        numBytesRandom =EncryptDecrypt.CalculoNumeroCifrado(password, level, order, pos);
                        for (int j = 0; j < numBytesRandom; j++)
                        {
                            *ptrBytesDisimulats = (byte)MiRandom.Next(byte.MaxValue + 1);
                            ptrBytesDisimulats++;
                        }
                        *ptrBytesDisimulats = *ptrBytes;
                        ptrBytesDisimulats++;
                        ptrBytes++;
                        pos += 2;
                    }
                    //para disumular el ultimo!
                    numBytesRandom = EncryptDecrypt.CalculoNumeroCifrado(password, level, order, pos);
                    for (int j = 0; j < numBytesRandom; j++)
                    {
                        *ptrBytesDisimulats = (byte)MiRandom.Next(byte.MaxValue + 1);
                        ptrBytesDisimulats++;
                    }
                }));
            }
            return bytesDisimulats;


        }
        public static byte[] Decrypt(byte[] bytes, byte[] password, LevelEncrypt level, Ordre order)
        {
            byte[] bytesTrobats;
            long longitudAux = bytes.Length;
            long longitud = 0;
            long pos = 0;
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
            bytesTrobats = new byte[longitud];//el ultimo es random tambien para disimular el ultimo real
            pos = 0;

            unsafe
            {
                byte* ptrBytes, ptrBytesTrobats;
                bytesTrobats.UnsafeMethod((unsBytesTrobats) => bytes.UnsafeMethod(unsBytes => {
                    ptrBytesTrobats = unsBytesTrobats.PtrArray;
                    ptrBytes = unsBytes.PtrArray;
                    for (long i = 0, f = longitud + 1; i < f; i++)
                    {
                        //recorro la array de bytes y pongo los bytes nuevos que tocan
                        ptrBytes += EncryptDecrypt.CalculoNumeroCifrado(password, level, order, pos);
                        //me salto los bytes random
                        *ptrBytesTrobats = *ptrBytes;
                        //pongo el byte original
                        ptrBytesTrobats++;
                        //avanzo
                        ptrBytes++;
                        pos += 2;
                    }
                }));
            }
            return bytesTrobats;
        }
    }
}
