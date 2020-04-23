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

        static unsafe byte*[] GetFilas(byte[] data, int lengthPassword)
        {
            byte* ptrData;
            byte*[] filas;
            int numFilas = data.Length / lengthPassword;
            bool inCompleta = data.Length % lengthPassword != 0;
            if (inCompleta)
                numFilas++;
            filas = new byte*[numFilas];
            fixed (byte* ptData = data)
            {
                ptrData = ptData;
                for (int i = 0, f = numFilas; i < f; i++)
                {
                    filas[i] = ptrData;
                    ptrData += lengthPassword;
                }
            }

            return filas;
        }
        static unsafe byte*[] OrdenaFilasEncrypt(byte*[] filas,byte[] password ,LevelEncrypt level, Ordre ordre)
        {
            byte*[] filasOrdenadas = new byte*[filas.Length];
            int[] posFilas = GetPosicionesFilas(password, filas.Length, level, ordre);

            //pongo las filas en su sitio
            for (int i = 0; i < filas.Length; i++)
            {
                filasOrdenadas[posFilas[i]] = filas[i];
            }

            return filasOrdenadas;
        }
        static unsafe byte[] ReadColumn(byte*[] filas, int column, bool isComplete)
        {
            byte[] columna;
            int numFilas = filas.Length;

            if (!isComplete)
                numFilas--;

            columna = new byte[numFilas];
            for (int i = 0, f = columna.Length; i < f; i++)
                columna[i] = filas[i][column];

            return columna;
        }
        static unsafe void WriteColumn(byte*[] filas, int column, byte* dataColumn, bool isComplete)
        {
            for (int i = 0, f = isComplete ? filas.Length : filas.Length - 1; i < f; i++)
            {
                filas[i][column] = *dataColumn;
                dataColumn++;
            }

        }
        static int[] GetPositionPassword(byte[] password)
        {
            byte[] passOrdenada = (byte[])password.Clone();//mirar que haga bien la copia!!
            int[] posPassword = new int[passOrdenada.Length];
            passOrdenada.Sort(SortMethod.QuickSort);

            //pongo las posiciones 

            return posPassword;

        }
        public static byte[] Encrypt(byte[] data,byte[] password,LevelEncrypt level,Ordre ordre)
        {
            bool filaCompleta;
            byte[] encrypted = new byte[data.Length];
            int[] posPassword = GetPositionPassword(password);
            int lineaFinalLenght = data.Length % password.Length;

            MemoryStream ms = new MemoryStream(encrypted);
            unsafe
            {
                byte*[] filas = GetFilas(data, password.Length);
                filas = OrdenaFilasEncrypt(filas,password, level, ordre);
                for(int i = 0; i < password.Length; i++)
                {
                    filaCompleta = posPassword[i] <= lineaFinalLenght;
                    ms.Write(ReadColumn(filas, posPassword[i], filaCompleta),0, filaCompleta?filas.Length:filas.Length-1);
                }
                
            }
            ms.Close();
            return encrypted;
        }
        public static byte[] Decrypt(byte[] data,byte[] password,LevelEncrypt level,Ordre ordre)
        {
            bool filaCompleta;
            byte[][] filas;
            byte[] decrypted = new byte[data.Length];
            int[] posPassword = GetPositionPassword(password);
            int lineaFinalLength = data.Length % password.Length;
            int numFilas;

            MemoryStream ms = new MemoryStream(decrypted);
            unsafe
            {
                byte* ptrData;
                byte*[] columnasOrdenadas = new byte*[posPassword.Length];
                numFilas=data.Length / columnasOrdenadas.Length;
                fixed (byte* ptData = data)
                {
                    ptrData = ptData;
                    for (int i = 0; i < posPassword.Length; i++)
                    {
                        columnasOrdenadas[posPassword[i]] = ptrData;
                        filaCompleta = posPassword[i] <= lineaFinalLength;
                        ptrData +=filaCompleta? numFilas:numFilas-1;
                    }
                    filas = OrdenaFilasDecrypt(columnasOrdenadas,password,lineaFinalLength,numFilas,level, ordre);
                }
                for (int i = 0; i < filas.Length; i++)
                    ms.Write(filas[i],0,filas[i].Length);

            }
            ms.Close();
            return decrypted;
        }

        private static unsafe byte[][] OrdenaFilasDecrypt(byte*[] columnasOrdenadas,byte[] password,int lineaFinalLength,int numFilas, LevelEncrypt level, Ordre ordre)
        {
            byte[][] filasDesordenadas = new byte[numFilas][];
            byte[][] filasOrdenadas = new byte[numFilas][];
            int lastFila = numFilas - 1;
            int[] posFilas;
            for (int i = 0, f = lastFila; i < f; i++)
                filasDesordenadas[i] = ReadLine(columnasOrdenadas, i, password.Length);
            filasDesordenadas[lastFila] = ReadLine(columnasOrdenadas,lastFila, lineaFinalLength);
            //las ordeno
            posFilas = GetPosicionesFilas(password, numFilas, level, ordre);
            for (int i = 0; i < numFilas; i++)
                filasOrdenadas[posFilas[i]] = filasDesordenadas[i];

            return filasOrdenadas;

        }

        private static int[] GetPosicionesFilas(byte[] password, int numFilas, LevelEncrypt level, Ordre ordre)
        {
            int[] posFilas = new int[numFilas];
            for (int i = 0; i < numFilas; i++)
                posFilas[i] = i;
            Perdut.EncryptDecrypt(posFilas, password, level, ordre);
            return posFilas;
        }

        private static unsafe byte[] ReadLine(byte*[] columnasOrdenadas, int linea, int lentgth)
        {
            byte[] data = new byte[lentgth];
            for (int i = 0; i < lentgth; i++)
                data[i] = columnasOrdenadas[i][linea];
            return data;
        }
    }
}
