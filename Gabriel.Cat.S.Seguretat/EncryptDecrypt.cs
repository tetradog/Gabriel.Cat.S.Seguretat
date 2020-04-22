using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    public enum LevelEncrypt
    {
        Lowest=1,
        Low,
        Normal,
        High,
        Highest
    }
    public enum PasswordEncrypt
    {
        Md5,
      //  Sha256,
        Nothing
    }
    public enum DataEncrypt
    {
        /// <summary>
        /// It is based on hiding data from random data, avoid (char)0 or/and two consecutive 0x0 
        /// </summary>
        Disimulat,
        /// <summary>
        /// It is the Cesar algorithm adapted, avoid (char)0 or/and two consecutive 0x0 
        /// </summary>
        Cesar,
        /// <summary>
        /// It is a method to disorder bytes using a password, avoid (char)0 or/and two consecutive 0x0 
        /// </summary>
        Perdut,
        OldLost
    }
    public static class EncryptDecrypt
    {
        public static readonly byte[] BytesChangeDefault = {
            0x0,
            0xFF,
            0xF4,
            0x5F
        };

        private delegate byte[] MetodoMultiKey(byte[] data, byte[] password, DataEncrypt dataEncrypt, PasswordEncrypt passwordEncrypt, LevelEncrypt level, Ordre order);

        public static int LenghtEncrypt(int lenghtDecrypt, byte[] password, DataEncrypt dataEncrypt, PasswordEncrypt passwordEncrypt, LevelEncrypt level, Ordre order)
        {
            int lengthEncrypt;
            password = password.EncryptNotReverse(passwordEncrypt);
            switch (dataEncrypt)
            {
                case DataEncrypt.Cesar: lengthEncrypt = Cesar.LenghtEncrtypt(lenghtDecrypt, password, level, order); break;
                case DataEncrypt.Perdut: lengthEncrypt = Perdut.LenghtEncrtypt(lenghtDecrypt, password, level, order); break;
                case DataEncrypt.Disimulat: lengthEncrypt = Disimulat.LenghtEncrtypt(lenghtDecrypt, password, level, order); break;
                case DataEncrypt.OldLost: lengthEncrypt = OldLost.LenghtEncrtypt(lenghtDecrypt, password, level, order);break;
                default: throw new ArgumentOutOfRangeException();
            }
            return lengthEncrypt;
        }
        public static int LenghtDecrypt(int lenghtEncrypt, byte[] password,DataEncrypt dataEncrypt,PasswordEncrypt passwordEncrypt, LevelEncrypt level, Ordre order)
        {
            int lengthDecrypt;
            password = password.EncryptNotReverse(passwordEncrypt);
            switch (dataEncrypt)
            {
                case DataEncrypt.Cesar: lengthDecrypt = Cesar.LenghtDecrypt(lenghtEncrypt, password, level, order);break;
                case DataEncrypt.Perdut: lengthDecrypt = Perdut.LenghtDecrypt(lenghtEncrypt, password, level, order); break;
                case DataEncrypt.Disimulat: lengthDecrypt = Disimulat.LenghtDecrypt(lenghtEncrypt, password, level, order); break;
                case DataEncrypt.OldLost: lengthDecrypt = OldLost.LenghtDecrypt(lenghtEncrypt, password, level, order); break;
                default:throw new ArgumentOutOfRangeException();
            }
            return lengthDecrypt;
        }
        public static byte[] EncryptNotReverse(this byte[] bytes, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5)
        {
            if (bytes.Length != 0)
                switch (passwordEncrypt)
                {
                    case PasswordEncrypt.Md5:
                        bytes =Serializar.GetBytes(bytes.Hash());
                        break;
                    case PasswordEncrypt.Nothing:
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            return bytes;
        }
        #region SobreCargaEncrypt
        public static byte[] Encrypt(this byte[] bytes, string password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("se requiere una password", "password");
            return Encrypt(bytes, Serializar.GetBytes(password), dataEncrypt, passwordEncrypt, level, order);
        }
        public static byte[] Encrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (password == null)
                throw new ArgumentNullException("password", "se requiere una password");
            return Encrypt(bytes, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order);
        }
        internal static byte[] Encrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt, PasswordEncrypt passwordEncrypt, LevelEncrypt level, Ordre order = Ordre.Consecutiu)
        {
            if (password == null)
                throw new ArgumentNullException("password", "se requiere una password");
            return Encrypt(bytes, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order);
        }
        #endregion
        internal static byte[] Encrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt, LevelEncrypt level, Ordre order)
        {
            byte[] bytesEncrypted = null;

            switch (dataEncrypt)
            {
                case DataEncrypt.Cesar:
                    bytesEncrypted = Cesar.Encrypt(bytes, password, level, order);
                    break;
                case DataEncrypt.Disimulat:
                    bytesEncrypted = Disimulat.Encrypt(bytes, password, level, order);
                    break;
                case DataEncrypt.Perdut:
                    bytesEncrypted = Perdut.Encrypt(bytes, password, level, order);
                    break;
                case DataEncrypt.OldLost:
                    bytesEncrypted = OldLost.Encrypt(bytes, password, level, order);
                    break;
                default: throw new ArgumentOutOfRangeException("dataEncrypt");
            }

            return bytesEncrypted;
        }
        #region SobreCargaDecrypt
        public static byte[] Decrypt(this byte[] bytes, string password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("se requiere una password", "password");
            return Decrypt(bytes, Serializar.GetBytes(password), dataEncrypt, passwordEncrypt, level, order);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Nothing, Ordre order = Ordre.Consecutiu)
        {
            if (password == null)
                throw new ArgumentNullException("password", "se requiere una password");
            return Decrypt(bytes, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order);
        }
        internal static byte[] Decrypt(this byte[] bytes, byte[] password, DataEncrypt dataEncrypt, PasswordEncrypt passwordEncrypt, LevelEncrypt level, Ordre order)
        {
            if (password == null)
                throw new ArgumentNullException("password", "se requiere una password");
            return Decrypt(bytes, password.EncryptNotReverse(passwordEncrypt), dataEncrypt, level, order);
        }
        #endregion
        internal static byte[] Decrypt(this byte[] bytes, byte[] password, DataEncrypt dataDecrypt, LevelEncrypt level, Ordre order)
        {
            if (password.Length == 0)
                throw new ArgumentException("Se requiere una password de longitud > 0");
            byte[] bytesDecrypted = null;

            switch (dataDecrypt)
            {
                case DataEncrypt.Cesar:
                    bytesDecrypted = Cesar.Decrypt(bytes, password, level, order);
                    break;
                case DataEncrypt.Disimulat:
                    bytesDecrypted = Disimulat.Decrypt(bytes, password, level, order);
                    break;
                case DataEncrypt.Perdut:
                    bytesDecrypted = Perdut.Decrypt(bytes, password, level, order);
                    break;
                case DataEncrypt.OldLost:
                    bytesDecrypted = OldLost.Decrypt(bytes, password, level, order);
                    break;
                default: throw new ArgumentOutOfRangeException("dataDecrypt");
            }

            return bytesDecrypted;
        }
        internal static int CalculoNumeroCifrado(byte[] password, LevelEncrypt level, Ordre order, int pos)
        {
            return Serializar.ToUShort(new byte[] { password.GetElementActual(order, pos), password.GetElementActual(order, pos + 1) }) * ((int)level + 1) * 2;
        }
        internal static int CalculoNumeroCifrado(byte[] password, LevelEncrypt level, Ordre order, long pos)
        {
            return CalculoNumeroCifrado(password, level, order, (int)(pos % int.MaxValue));
        }
        #region MultiKey
        #region Escollir clau per caracter
        //parte en comun :)
        private static byte[] EncryptDecryptCommun(MetodoMultiKey metodo, byte[] data, byte[][] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordsEncrypt, LevelEncrypt level, Ordre order)
        {
            //por testear!!
            int numCanvis = 0;
            byte[] passwordActual;
            DataEncrypt dataEncryptAct;
            PasswordEncrypt passwordEncryptAct;
            byte[] bytesResult = new byte[0];
            byte[] byteResultAux;
            List<byte[]> dataSplited = data.Split(bytesChange);
            List<byte[]> dataResultSplited = new List<byte[]>();
            //opero
            passwordEncryptAct = passwordsEncrypt.GetElementActual(order, numCanvis);
            dataEncryptAct = dataEncrypt.GetElementActual(order, numCanvis);
            passwordActual = passwords.GetElementActual(order, numCanvis);
            byteResultAux = metodo(dataSplited[0], passwordActual, dataEncryptAct, passwordEncryptAct, level, order);
            if (data.SearchArray(bytesChange) > -1)//si tiene marca la pongo
                byteResultAux = byteResultAux.AddArray(bytesChange);
            dataResultSplited.Add(byteResultAux);
            numCanvis++;
            for (int i = 1; i < dataSplited.Count - 1; i++)
            {

                passwordEncryptAct = passwordsEncrypt.GetElementActual(order, numCanvis);
                dataEncryptAct = dataEncrypt.GetElementActual(order, numCanvis);
                passwordActual = passwords.GetElementActual(order, numCanvis);
                byteResultAux = metodo(dataSplited[i], passwordActual, dataEncryptAct, passwordEncryptAct, level, order).AddArray(bytesChange);
                dataResultSplited.Add(byteResultAux);
                numCanvis++;

            }
            if (dataSplited.Count > 1)
            {
                if (dataSplited[dataSplited.Count - 1].Length != 0)
                {//si no acaba en la marca es que hay bytes
                    passwordEncryptAct = passwordsEncrypt.GetElementActual(order, numCanvis);
                    dataEncryptAct = dataEncrypt.GetElementActual(order, numCanvis);
                    passwordActual = passwords.GetElementActual(order, numCanvis);
                    byteResultAux = metodo(dataSplited[dataSplited.Count - 1], passwordActual, dataEncryptAct, passwordEncryptAct, level, order).AddArray(bytesChange);
                    dataResultSplited.Add(byteResultAux);

                }
                else
                    dataResultSplited.Add(bytesChange);//añado la marca a los bytes finales
            }

            return bytesResult.AddArray(dataResultSplited.ToArray());
        }
        //los bytes para el cambio tienen que ser unicos...y no se pueden dar dentro de los datos...
        #region SobreCargaEncrypt
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, passwordEncrypt, level, escogerKey);
        }

        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }

        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, dataEncrypt, passwordEncrypt, level, escogerKey);
        }

        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Encrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }
        #endregion
        public static byte[] Encrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return EncryptDecryptCommun(Encrypt, bytes, passwords, bytesChange, dataEncrypt, passwordEncrypt, level, escogerKey);
        }
        #region SobreCargaDecrypt
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }

        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, BytesChangeDefault, dataEncrypt, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, bytesChange, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            if (passwords == null || dataEncrypt == null || passwordEncrypt == null)
                throw new ArgumentNullException();
            List<byte[]> passwordBytes = new List<byte[]>();
            for (int i = 0; i < passwords.Length; i++)
                passwordBytes.Add(Serializar.GetBytes(passwords[i]));
            return Decrypt(bytes, passwordBytes.ToArray(), bytesChange, dataEncrypt, passwordEncrypt, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt dataEncrypt = DataEncrypt.Cesar, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt passwordEncrypt = PasswordEncrypt.Md5, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, bytesChange, dataEncrypt, new PasswordEncrypt[] { passwordEncrypt }, level, escogerKey);
        }
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, PasswordEncrypt[] passwordEncrypt, DataEncrypt dataEncrypt = DataEncrypt.Cesar, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return Decrypt(bytes, passwords, bytesChange, new DataEncrypt[] { dataEncrypt }, passwordEncrypt, level, escogerKey);
        }
        #endregion
        public static byte[] Decrypt(this byte[] bytes, byte[][] passwords, byte[] bytesChange, DataEncrypt[] dataEncrypt, PasswordEncrypt[] passwordEncrypt, LevelEncrypt level = LevelEncrypt.Normal, Ordre escogerKey = Ordre.Consecutiu)
        {
            return EncryptDecryptCommun(Decrypt, bytes, passwords, bytesChange, dataEncrypt, passwordEncrypt, level, escogerKey);
        }

        #endregion
        #endregion
    }
}
