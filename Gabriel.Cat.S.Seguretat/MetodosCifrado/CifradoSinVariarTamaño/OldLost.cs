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

        private static unsafe byte*[] GetFilas(byte* ptData,int lengthData, int lengthPassword)
        {
            byte* ptrData;
            byte*[] filas;
            int numFilas = lengthData / lengthPassword;
            bool inCompleta = lengthData % lengthPassword != 0;
            if (inCompleta)
                numFilas++;
            filas = new byte*[numFilas];
       
                ptrData = ptData;
                for (int i = 0, f = numFilas; i < f; i++)
                {
                    filas[i] = ptrData;
                    ptrData += lengthPassword;
                }
            

            return filas;
        }
        private static unsafe byte*[] OrdenaFilasEncrypt(byte*[] filas,byte[] password ,LevelEncrypt level, Ordre ordre)
        {
            byte*[] filasDesordenadas = new byte*[filas.Length];
            int[] posFilas = GetPosicionesFilas(password, filas.Length, level, ordre);

            //pongo las filas en su sitio
            for (int i = 0; i < filas.Length; i++)
            {
                filasDesordenadas[posFilas[i]] = filas[i];
            }

            return filasDesordenadas;
        }
        private static unsafe byte[] ReadColumn(byte*[] filas, int column, int length)//la longitud cambia porque no tiene por que ser exacto...
        {
            byte[] columna;

            columna = new byte[length];
            for (int i = 0, f = columna.Length; i < f; i++)
                columna[i] = filas[i][column];

            return columna;
        }
        private static unsafe void WriteColumn(byte*[] filas, int column, byte* dataColumn, int length)
        {
            for (int i = 0; i < length; i++)
            {
                filas[i][column] = *dataColumn;
                dataColumn++;
            }

        }
        private static int[] GetPositionPassword(byte[] password)
        {
            int aux;
            byte[] passOrdenada = (byte[])password.Clone();//mirar que haga bien la copia!!
            int[] posPassword = new int[passOrdenada.Length];
            SortedList<int, int> dicPosiciones = new SortedList<int, int>();

            passOrdenada.Sort(SortMethod.QuickSort);

            //pongo las posiciones 
            for (int i = 0; i < password.Length; i++)
            {
                if (dicPosiciones.ContainsKey(passOrdenada[i]))
                    aux = dicPosiciones[passOrdenada[i]]+1;
                else aux = 0;
                posPassword[i] = password.IndexOf(aux, passOrdenada[i]);
                if (dicPosiciones.ContainsKey(passOrdenada[i]))
                    dicPosiciones.Remove(passOrdenada[i]);
                dicPosiciones.Add(passOrdenada[i], posPassword[i]);
            }
            return posPassword;

        }

        public static byte[] Encrypt(byte[] data,byte[] password,LevelEncrypt level,Ordre ordre)
        {
            int lengthFila;
            byte[] encrypted = new byte[data.Length];
            int[] posPassword = GetPositionPassword(password);
            int lineaFinalLenght = data.Length % password.Length;
            int length = data.Length < password.Length ? data.Length : password.Length;
            MemoryStream ms = new MemoryStream(encrypted);

            if (lineaFinalLenght == 0)//si no hay una incompleta quiere decir que acaba junto con el ultimo caracter de la password
                lineaFinalLenght = password.Length;

            unsafe
            {
                byte*[] filas;
                fixed (byte* ptData = data)
                {
                    filas = GetFilas(ptData, data.Length, password.Length);
                    filas = OrdenaFilasEncrypt(filas, password, level, ordre);
                    for (int i = 0; i < password.Length && i < data.Length; i++)
                    {
                        lengthFila = (posPassword[i] != filas.Length - 1)?length:lineaFinalLenght;
                        ms.Write(ReadColumn(filas, i, lengthFila), 0, lengthFila);
                    }
                }
                
            }
            ms.Close();
            return encrypted;
        }
        public static byte[] Decrypt(byte[] data,byte[] password,LevelEncrypt level,Ordre ordre)
        {
            bool filaCompleta;
            byte[][] filas;
            int numFilas;
            byte[] decrypted = new byte[data.Length];
            int[] posPassword = GetPositionPassword(password);
            int lineaFinalLength = data.Length % password.Length;
            MemoryStream ms = new MemoryStream(decrypted);

            if (lineaFinalLength == 0)//si no hay una incompleta quiere decir que acaba junto con el ultimo caracter de la password
                lineaFinalLength = password.Length;


            unsafe
            {
                byte* ptrData;
                byte*[] columnasOrdenadas = new byte*[posPassword.Length];

                numFilas=data.Length / columnasOrdenadas.Length;

                if (data.Length % columnasOrdenadas.Length != 0)
                    numFilas++;

                fixed (byte* ptData = data)
                {
                    ptrData = ptData;
                    for (int i = 0; i < posPassword.Length; i++)
                    {
                        columnasOrdenadas[posPassword[i]] = ptrData;
                        filaCompleta = posPassword[i] != numFilas- 1;
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

            return Perdut.Encrypt(posFilas, password, level, ordre);
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
