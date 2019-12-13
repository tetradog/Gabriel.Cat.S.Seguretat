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
        public static IList<Bitmap> GetBitmaps(this IList<Bitmap> lstBmps, int length,LevelEncrypt level)
        {
 

            List<Bitmap> bmps = new List<Bitmap>();
            long pos = 0;
            int i = 0;
            while (pos < length)
            {
                bmps.Add(lstBmps[i].Clone(System.Drawing.Imaging.PixelFormat.Format32bppArgb));
                pos += lstBmps[i++].MaxLength(level);
            }
            return bmps;
        }
        public static IList<Bitmap> Encrypt(this IList<Bitmap> lstBmps, byte[] data, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, LevelEncrypt level = LevelEncrypt.Normal, Ordre order = Ordre.Consecutiu)
        {

            data = EncryptDecrypt.Encrypt(data, password, dataEncrypt, passwordEncrypt, level, order);
            return lstBmps.SetData(data,level);
        }
        public static byte[] Decrypt(this IList<Bitmap> lstBmps,byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, LevelEncrypt level = LevelEncrypt.Normal, Ordre order = Ordre.Consecutiu)
        {
            byte[] data = lstBmps.GetData(level);
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
            data = data.SubArray(data.SearchArray(EncryptDecrypt.BytesChangeDefault));//quito la marca fin
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
        public static IList<Bitmap> SetData(this IList<Bitmap> bmpsToSetData, byte[] data,LevelEncrypt level)
        {
            if (bmpsToSetData.MaxLength(level) < data.Length+EncryptDecrypt.BytesChangeDefault.Length)
                throw new InsufficientMemoryException();
            IList<Bitmap> bmps = bmpsToSetData.GetBitmaps(data.Length + EncryptDecrypt.BytesChangeDefault.Length, level);

            unsafe
            {
                byte* ptrData;
                fixed(byte* ptData = data.AddArray(EncryptDecrypt.BytesChangeDefault,new byte[bmpsToSetData.MaxLength(level)-data.Length-EncryptDecrypt.BytesChangeDefault.Length]))//añado marca fin
                {
                    ptrData = ptData;
                    for (int i = 0; i < bmps.Count; i++)
                       ptrData= bmps[i].SetData(ptrData, level);
                }
            }



            return bmps;
        }
        private unsafe static byte* SetData(this Bitmap bmp, byte* data, LevelEncrypt level)
        {
            bmp.TrataBytes((MetodoTratarBytePointer)((ptrData) =>
            {//se recorre todo el bmp y se pone la informacion en su sitio teniendo en cuenta el nivel de encriptación


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
