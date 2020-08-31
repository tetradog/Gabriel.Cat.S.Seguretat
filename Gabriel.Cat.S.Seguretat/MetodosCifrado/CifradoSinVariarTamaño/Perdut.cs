using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    public static class Perdut
    {
        public static int LenghtEncrtypt(int lengthDecrypt, byte[] password = default, LevelEncrypt level = default, Ordre order = default)
        {
            return lengthDecrypt;
        }
        public static int LenghtDecrypt(int lenghtEncrypt, byte[] password = default, LevelEncrypt level = default, Ordre order = default)
        {
            return lenghtEncrypt;
        }
        public static Context<T> InitContextDecrypt<T>(T[] data, byte[] password = default, LevelEncrypt level = default, Ordre ordre = default, long inicioIn=0,long finIn=-1) where T:unmanaged
        {
            Context<T> context = new Context<T>();
       
                context.ForI =context.DataOut.Length - 1;
            if (context.ForF < 0)
                context.ForF =  0;

            context.DataIn = data;
            context.ForI = inicioIn;
            if (finIn > 0)
            {
                context.ForF = finIn;
                context.DataOut = new T[finIn - inicioIn];
            }
            else
            {
                context.ForF = data.Length;
                if (inicioIn == 0)
                    context.DataOut = new T[data.Length];
                else context.DataOut = new T[finIn - inicioIn];
            }
            context.Aux = 0;
            return context;
        }


        public static T[] Decrypt<T>(T[] data, byte[] password, LevelEncrypt level, Ordre ordre) where T : unmanaged
        {
            Context<T> context = InitContextDecrypt<T>(data,password,level,ordre);
            return Decrypt(context, password, level, ordre).DataOut;
        }
        public static Context<T> Decrypt<T>(Context<T> context, byte[] password, LevelEncrypt level, Ordre ordre) where T : unmanaged
        {
            return ComunEncryptDecrypt(context, password, level, ordre, false);
        }

        public static Context<T> InitContextEncrypt<T>(T[] data, byte[] password = default, LevelEncrypt level = default, Ordre ordre = default, long inicioIn = 0, long finIn = -1) where T : unmanaged
        {
            return InitContextDecrypt<T>(data, password, level, ordre, inicioIn, finIn);
        }
        public static T[] Encrypt<T>(T[] data, byte[] password, LevelEncrypt level, Ordre ordre) where T : unmanaged
        {
            Context<T> context = InitContextEncrypt<T>(data, password, level, ordre);
            return Encrypt(context, password, level, ordre).DataOut;
        }
        public static Context<T> Encrypt<T>(Context<T> context, byte[] password, LevelEncrypt level, Ordre ordre) where T : unmanaged
        {
            return ComunEncryptDecrypt(context, password, level, ordre, true);
        }


        static Context<T> ComunEncryptDecrypt<T>(Context<T> context, byte[] password, LevelEncrypt level, Ordre order, bool toEncrypt) where T : unmanaged
        {
            int f = (int)level + 1;
            for (; context.Aux < f && context.Continua; context.Aux++)//repito el proceso como nivel de seguridad :D
            {
                TractaPerdut(context, password, level, order, toEncrypt);//si descifra ira hacia atrás
            }
            if(!context.Continua)
                 context.Aux--;
            return context;
        }



        static void TractaPerdut<T>(Context<T> context, byte[] password, LevelEncrypt level, Ordre order, bool leftToRight) where T : unmanaged
        {
            long posAux;
            int direccion = leftToRight ? 1 : -1;

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
                    //compruebo que no ha acabado de forma forzada y que no se haya acabado por casualidad (osea lo cancelan cuando acababa el proceso)
                     if(!context.Continua&&!(leftToRight ? context.ForI <= context.ForF : context.ForI >= context.ForF))
                          context.ForI -= direccion;
                }
            }

        }

    }
}
