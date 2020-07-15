﻿using Gabriel.Cat.S.Extension;
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

        public static T[] Decrypt<T>(T[] bytes, byte[] password, LevelEncrypt level, Ordre ordre) where T : unmanaged
        {
            return ComunEncryptDecrypt(bytes, password, level, ordre, false);
        }

        public static T[] Encrypt<T>(T[] bytes, byte[] password, LevelEncrypt level, Ordre ordre) where T : unmanaged
        {
            return ComunEncryptDecrypt(bytes, password, level, ordre, true);
        }

        public static int LenghtDecrypt(int lenghtEncrypt, byte[] password, LevelEncrypt level, Ordre order)
        {
            return lenghtEncrypt;
        }
         static T[] ComunEncryptDecrypt<T>(T[] bytes, byte[] password, LevelEncrypt level, Ordre order, bool toEncrypt) where T:unmanaged
        {
            bytes = bytes.SubArray(0,bytes.Length);//optimizar...si se puede claro 

            unsafe
            {
                bytes.UnsafeMethod((ptrBytes) =>
                {
                    for (int i = 0, f = (int)level + 1; i < f; i++)//repito el proceso como nivel de seguridad :D
                    {
                        TractaPerdut(ptrBytes, password, level, order, toEncrypt);//si descifra ira hacia atrás
                    }

                });

            }
            return bytes;
        }

       

         static unsafe void TractaPerdut<T>(UnsafeArray<T> ptrBytes, byte[] password, LevelEncrypt level, Ordre order, bool leftToRight) where T:unmanaged
        {//va bien :D
            T aux;
            long posAux;
            int direccion = leftToRight ? 1 : -1;

            T* ptBytes = ptrBytes.PtrArray;//creo que optmizo un poquito al no entrar en la propiedad :D
            for (long i = leftToRight ? 0 : ptrBytes.Length - 1, f = leftToRight ? ptrBytes.Length - 1 : 0; leftToRight ? i <= f : i >= f; i += direccion)
            {
                posAux = (Seguretat.EncryptDecrypt.CalculoNumeroCifrado(password, level, order, i) + i) % ptrBytes.Length;
                aux = ptBytes[posAux];
                ptBytes[posAux] = ptBytes[i];
                ptBytes[i] = aux;
            }

        }

    }
}
