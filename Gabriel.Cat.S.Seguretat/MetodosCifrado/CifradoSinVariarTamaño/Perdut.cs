using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    public static class Perdut
    {
        public static int LenghtEncrtypt(int lengthDecrypt, byte[] password, LevelEncrypt level, Ordre order)
        {
            return lengthDecrypt;
        }
        public static int LenghtDecrypt(int lenghtEncrypt, byte[] password, LevelEncrypt level, Ordre order)
        {
            return lenghtEncrypt;
        }
        public static Context<T> Decrypt<T>(Context<T> context, byte[] password, LevelEncrypt level, Ordre ordre) where T : unmanaged
        {
            return ComunEncryptDecrypt(context, password, level, ordre, false);
        }

        public static Context<T> Encrypt<T>(Context<T> context, byte[] password, LevelEncrypt level, Ordre ordre) where T : unmanaged
        {
            return ComunEncryptDecrypt(context, password, level, ordre, true);
        }


        static Context<T> ComunEncryptDecrypt<T>(Context<T> context, byte[] password, LevelEncrypt level, Ordre order, bool toEncrypt) where T : unmanaged
        {
            for (int i = context.Aux, f = (int)level + 1; i < f && context.Continua; context.Aux++)//repito el proceso como nivel de seguridad :D
            {
                TractaPerdut(context, password, level, order, toEncrypt);//si descifra ira hacia atrás
            }

            return context;
        }



        static void TractaPerdut<T>(Context<T> context, byte[] password, LevelEncrypt level, Ordre order, bool leftToRight) where T : unmanaged
        {
            long posAux;
            int direccion = leftToRight ? 1 : -1;
            if (context.ForI < 0)
                context.ForI = leftToRight ? 0 : context.DataOut.Length - 1;
            if (context.ForF < 0)
                context.ForF = leftToRight ? context.DataOut.Length - 1 : 0;
            unsafe
            {
                T* ptrBytesOut;
                fixed (T* ptBytesIn = context.DataIn)
                fixed (T* ptBytesOut = context.DataOut)
                {
                    ptrBytesOut = ptBytesOut;
                    for (; (leftToRight ? context.ForI <= context.ForF : context.ForI >= context.ForF) && context.Continua; context.ForI += direccion)
                    {
                        posAux = (Seguretat.EncryptDecrypt.CalculoNumeroCifrado(password, level, order, context.ForI) + context.ForI) % context.DataIn.Length;
                        ptrBytesOut[posAux] = ptBytesIn[context.ForI];

                    }
                }
            }

        }

    }
}
