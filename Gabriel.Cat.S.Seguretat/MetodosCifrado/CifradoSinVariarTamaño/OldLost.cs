using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.IO;

namespace Gabriel.Cat.S.Seguretat
{

    public static class OldLost
    {
        public static int LenghtEncrtypt(int lengthDecrypt, byte[] password=default, LevelEncrypt level = default, Ordre order = default)
        {
            return lengthDecrypt;
        }
        public static int LenghtDecrypt(int lenghtEncrypt, byte[] password = default, LevelEncrypt level = default, Ordre order = default)
        {
            return lenghtEncrypt;
        }

       public static T[] Encrypt<T>(T[] dataOriginal,byte[] password, LevelEncrypt level = default, Ordre order = default){
           T[] dataEncryptada=new T[dataOriginal.Length];
           int[] posciones=GetPosiciones(password,level,order);

           for(int i=0,pos=0,inicioFila;i<dataOriginal.Length;i++){
                if(pos==0)
                  inicioFila=i;
               dataEncryptada[i]=dataOriginal[posciones[pos]+inicioFila];
               pos=(pos+1)%posciones.Length;
              
           }
           return dataEncryptada;
       }

       public static T[] Decrypt<T>(T[] dataEncrypted,byte[] password = default, LevelEncrypt level = default, Ordre order = default){
            T[] dataDecrypted=new T[dataEncrypted.Length];
           int[] posciones=GetPosiciones(password,level,order);

           for(int i=0,pos=0,inicioFila;i<dataEncrypted.Length;i++){
                if(pos==0)
                  inicioFila=i;
               dataDecrypted[i]=dataEncrypted[posciones[pos]+inicioFila];
               pos=(pos+1)%posciones.Length;
              
           }
           return dataEncryptada;
       }

       private static int[] GetPosiciones(byte[] password,LevelEncrypt level,Ordre ordre){
            int[] posiciones=new int[password.Length];
            for(int i=0;i<posiciones.Length;i++)
                posiciones[i]=i;
            return Perdut.Encrypt(posiciones,password,level,ordre);    
       }
    }
}
