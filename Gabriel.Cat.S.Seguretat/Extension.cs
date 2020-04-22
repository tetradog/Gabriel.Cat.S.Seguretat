using Gabriel.Cat.S.Seguretat;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
//falta probar
namespace Gabriel.Cat.S.Extension
{
    public static class Extension
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <param name="path"></param>
        /// <param name="key"></param>
        /// <param name="lengthParte">El archivo final estará segmentado en partes el tamaño final de cada parte sera este.</param>
        public static void Save(this byte[] data, string path, Key key = null, int lengthParte = 1024 * 1024 * 150)
        {
            if (lengthParte < 1)
                throw new ArgumentOutOfRangeException("lenghtParte");

            const int MARGENRAM = 1024;
            const int LENGTHINT = 4;
            System.IO.DriveInfo disco = new System.IO.DriveInfo(System.IO.Path.GetPathRoot(path));
            int longitudFinalArchivo = LENGTHINT;//NumPartes,Partes(Length,Data)
            int partes = 1;
            FileStream file = null;
            BinaryWriter bw = null;
            byte[] datosAPoner;

            try
            {
                file = new FileStream(path, FileMode.Create);
                bw = new BinaryWriter(file);
                if (disco.IsReady)
                {
                    if (data.Length < lengthParte)
                    {
                        lengthParte = data.Length;

                    }
                    else
                    {
                        partes += data.Length / lengthParte;
                    }
                    for (int i = 0; i < partes - 1; i++)
                    {
                        longitudFinalArchivo += LENGTHINT + (key == null ? (lengthParte) : key.LengthEncrypt(lengthParte));
                    }
                    if (data.Length != lengthParte)
                        longitudFinalArchivo += LENGTHINT + (key == null ? (data.Length % lengthParte) : key.LengthEncrypt(data.Length % lengthParte));

                    if (disco.TotalFreeSpace - MARGENRAM > longitudFinalArchivo)
                    {
                        bw.Write(partes);
                        for (int i = 0, f = partes - 1, pos = 0; i < f; i++)
                        {
                            datosAPoner = data.SubArray(pos, lengthParte);
                            if (key != null)
                            {
                                datosAPoner = key.Encrypt(datosAPoner);
                            }
                            bw.Write(datosAPoner.Length);
                            bw.Write(datosAPoner);

                            pos += lengthParte;
                            bw.Flush();
                        }
                        datosAPoner = data.SubArray((partes - 1) * lengthParte, data.Length - ((partes - 1) * lengthParte));
                        if (key != null)
                        {
                            datosAPoner = key.Encrypt(datosAPoner);
                        }

                        bw.Write(datosAPoner.Length);
                        bw.Write(datosAPoner);
                        bw.Flush();
                    }
                    else
                    {
                        throw new InsufficientMemoryException();
                    }
                }
                else
                {
                    throw new Exception("El disco no esta preparado...");
                }
            }
            catch { throw; }
            finally
            {
                if (bw != null)
                    bw.Close();
                if (file != null)
                    file.Close();
            }
        }

        public static byte[] Load(this FileInfo file, Key key = null)
        {
            const int LENGTHINT = 4;
            FileStream fs = new FileStream(file.FullName, FileMode.Open);
            BinaryReader br = new BinaryReader(fs);
            int partes = br.ReadInt32();
            int auxLenght;
            int lenght = 0;
            int index = 0;
            byte[] bytesDecrypted;
            for (int i = 0; i < partes; i++)
            {
                auxLenght = br.ReadInt32();
                lenght += key != null ? key.LengthDecrypt(auxLenght) : auxLenght;
                br.BaseStream.Position += auxLenght;
            }
            br.BaseStream.Position = LENGTHINT;
            bytesDecrypted = new byte[lenght];
            for (int i = 0; i < partes; i++)
            {
                auxLenght = br.ReadInt32();
                bytesDecrypted.SetArray(index, key != null ? key.Decrypt(br.ReadBytes(auxLenght)) : br.ReadBytes(auxLenght));
                index += auxLenght;

            }
            return bytesDecrypted;
        }
        public static void Encrypt(this FileInfo file, string pathDestino, Key key, long lengthParte = 1024 * 1024 * 150)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            const int MARGENRAM = 1024;
            const int LENGTHINT = 4;
            System.IO.DriveInfo disco = new System.IO.DriveInfo(System.IO.Path.GetPathRoot(pathDestino));

            FileStream fsIn=null;
            FileStream fsOut = null;
            BinaryReader brIn = null;
            BinaryWriter bwOut = null;

            int partes = 1;
            byte[] datos;
            int lenghtFinalParte;
            if (file.Length < lengthParte)
                lengthParte = file.Length;
            else
            {
                partes += (int)(file.Length / lengthParte);
            }

            lenghtFinalParte = (int)lengthParte;
            if (!disco.IsReady)
                throw new Exception("Disco no preparado");
            if (file.Length == lengthParte)
            {
                if (disco.AvailableFreeSpace - MARGENRAM < LENGTHINT + LENGTHINT + key.LengthEncrypt(lenghtFinalParte))
                    throw new InsufficientMemoryException();
            }
            else
            {
                if (disco.AvailableFreeSpace - MARGENRAM < LENGTHINT + (LENGTHINT + key.LengthEncrypt(lenghtFinalParte)) * partes + LENGTHINT + key.LengthEncrypt((int)(file.Length % lengthParte)))
                    throw new InsufficientMemoryException();
            }
            try
            {
                fsIn = new FileStream(file.FullName, FileMode.Open);
                fsOut = new FileStream(pathDestino, FileMode.Create);
                brIn = new BinaryReader(fsIn);
                bwOut = new BinaryWriter(fsOut);

                bwOut.Write(partes);
                for (int i = 0; i < partes; i++)
                {
                    datos = brIn.ReadBytes(lenghtFinalParte);
                    datos = key.Encrypt(datos);
                    bwOut.Write(datos.Length);
                    bwOut.Write(datos);
                    bwOut.Flush();
                    
                }
                if (file.Length != lengthParte)
                {
                    datos = brIn.ReadBytes((int)(file.Length % lengthParte));
                    datos = key.Encrypt(datos);
                    bwOut.Write(datos.Length);
                    bwOut.Write(datos);
                    bwOut.Flush();
                }
                bwOut.Close();
                brIn.Close();
                fsIn.Close();
                fsOut.Close();
            }
            catch { throw; }
            finally
            {
                if (bwOut != null)
                    bwOut.Close();
                if (brIn != null)
                    brIn.Close();
                if (fsIn != null)
                    fsIn.Close();
                if (fsOut != null)
                    fsOut.Close();

            }
        }


        public static byte[] ReadToEnd(this BinaryReader br)
        {
            return br.ReadBytes((int)(br.BaseStream.Length - br.BaseStream.Position));
        }
    }
}
