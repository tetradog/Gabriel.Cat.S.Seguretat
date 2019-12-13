using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    public static class BitmapContainer
    {
        public static IList<Bitmap> Encrypt(this IList<Bitmap> lstBmps, byte[] data, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, LevelEncrypt level = LevelEncrypt.Normal, Ordre order = Ordre.Consecutiu)
        {
            
            if (lstBmps.MaxLength(level) < EncryptDecrypt.LenghtEncrypt(data.Length, password, dataEncrypt, passwordEncrypt, level, order)+EncryptDecrypt.BytesChangeDefault.Length)
                throw new InsufficientMemoryException();

            List<Bitmap> bmps = new List<Bitmap>();
            long pos = 0;
            int i = 0;
            byte[] aux;

            data = EncryptDecrypt.Encrypt(data, password, dataEncrypt, passwordEncrypt, level, order);
            data = data.AddArray(EncryptDecrypt.BytesChangeDefault);//pongo marcaFin
            while (pos < data.Length)
            {
                bmps.Add(lstBmps[i].Clone(System.Drawing.Imaging.PixelFormat.Format32bppArgb));
                pos += lstBmps[i++].MaxLength(level);
            }
            unsafe
            {
                byte* ptrData;
                byte* ptrAux;
                fixed (byte* ptData = data)
                {
                    pos = 0;
                    ptrData = ptData;
                    for (int j = 0, f = bmps.Count - 1; j < f; j++)
                    {
                        pos += bmps[j].MaxLength(level);
                        ptrData = bmps[j].SetData(ptrData, level);
                    }
                    //el ultimo no ocupará toda la imagen por eso lo pongo al final :)
                    aux = new byte[bmps[bmps.Count - 1].MaxLength(level)];
                    fixed (byte* ptAux = aux)
                    {
                        ptrAux = ptAux;

                        for (int l = (int)pos; l < data.Length; l++)
                        {
                            *ptrAux = *ptrData;
                            ptrAux++;
                            ptrData++;
                        }
                        ptrData = ptAux;
                        bmps[bmps.Count - 1].SetData(ptrData, level);
                    }
                }
            }


            return bmps;
        }
        public static byte[] Decrypt(this IList<Bitmap> lstBmps,byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, LevelEncrypt level = LevelEncrypt.Normal, Ordre order = Ordre.Consecutiu)
        {
            byte[] data = lstBmps.GetData(level);
            data = data.SubArray(data.SearchArray(EncryptDecrypt.BytesChangeDefault));//quito la marca fin
            return EncryptDecrypt.Decrypt(data, password, dataEncrypt, passwordEncrypt, level, order);
           
        }
        public static byte[] GetData(this IList<Bitmap> bmps,LevelEncrypt level)
        {
            byte[] data = new byte[bmps.MaxLength(level)];
            unsafe
            {
                byte* ptrData;
                byte* ptrBmp;
                fixed(byte* ptData = data)
                {
                    ptrData = ptData;
                    for(int i=0;i<bmps.Count;i++)
                    {
                        
                      ptrBmp = bmps[i].GetData(level);
                      for(long j=0,jF=bmps[i].MaxLength(level);j<jF;j++)
                        {
                            *ptrData = *ptrBmp;
                            ptrBmp++;
                            ptrData++;
                        }
                        

                    }
                }
            }
            return data;
        }
        public unsafe static byte* GetData(this Bitmap bmp,LevelEncrypt level)
        {
            byte* ptrDataOri;
            byte* ptrData;
            byte* ptrBmp;
            fixed(byte* ptData=new byte[bmp.MaxLength(level)])
            {
                ptrDataOri = ptData;
                ptrData = ptrDataOri;

                fixed(byte* ptBmp=bmp.GetBytes())
                {
                    ptrBmp = ptBmp;
                    //recorro el bmp y lo pongo en ptrData

                }
            }
            return ptrDataOri;
        }
        public unsafe static byte* SetData(this Bitmap bmp, byte* data, LevelEncrypt level)
        {
            bmp.TrataBytes((MetodoTratarBytePointer)((ptrData) =>
            {


            }));

            return data;
        }
        public static long MaxLength(this IList<Bitmap> lstBmps, LevelEncrypt level)
        {
            long max = 0;
            for (int i = 0; i < lstBmps.Count; i++)
                max += lstBmps[i].MaxLength(level);
            return max;
        }
        public static long MaxLength(this Bitmap bmp, LevelEncrypt level)
        {
            const int ARGB = 4;
            return (bmp.Height * bmp.Width * ARGB) / (((int)level) + 1);
        }
    }
}
