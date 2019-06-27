using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml.Linq;

namespace Gabriel.Cat.S.Seguretat
{
    public class Key : IClonable<Key>, IDisposable
    {

        public class ItemKey : IClonable<ItemKey>
        {

            public ItemKey(int methodData = 0, int methodPassword = 0, bool randomKey = true, int lenghtRandomKey = 15)
            {
                MethodData = methodData;
                MethodPassword = methodPassword;
                if (!randomKey)
                    Password = "";
                else
                    GenerateRandomKey(lenghtRandomKey);
            }
            public ItemKey(int methodData = 0, int methodPassword = 0, string password = null) : this(methodData, methodPassword, password == null)
            {
                if (password != null)
                    Password = password;
            }
            public int MethodData { get; set; }
            public int MethodPassword { get; set; }
            public string Password { get; set; }

            public void GenerateRandomKey(int lenght = 15)
            {
                if (lenght < 0)
                    throw new ArgumentOutOfRangeException();
                StringBuilder str = new StringBuilder();
                for (int i = 0; i < lenght; i++)
                    str.Append((char)MiRandom.Next(256));

                Password = str.ToString();
            }

            public ItemKey Clon()
            {
                return new ItemKey(MethodData, MethodPassword, Password);
            }
            public override bool Equals(object obj)
            {
                return Equals(obj as ItemKey);
            }
            public bool Equals(ItemKey other)
            {
                return other != null && Password.Equals(other.Password) && MethodData == other.MethodData && MethodPassword == other.MethodPassword;
            }
        }


        public class ItemEncryptationData : IClonable<ItemEncryptationData>
        {
            public delegate byte[] MethodEncryptReversible(byte[] data, string password, bool encrypt = true);
            public delegate int MethodGetLenght(int lenght);

            public MethodEncryptReversible MethodData { get; set; }
            public MethodGetLenght MethodLenghtEncrypted { get; set; }
            public MethodGetLenght MethodLenghtDecrypted { get; set; }
            public bool LengthVariable;
            public ItemEncryptationData(MethodEncryptReversible methodData, MethodGetLenght methodGetLenghtEncrypted, MethodGetLenght methodGetLenghtDecrypted, bool lenghtVariable)
            {
                MethodData = methodData;
                MethodLenghtDecrypted = methodGetLenghtDecrypted;
                MethodLenghtEncrypted = methodGetLenghtEncrypted;
                LengthVariable = lenghtVariable;
            }
            public byte[] Encrypt(byte[] data, string key)
            {
                return MethodData(data, key);
            }
            public byte[] Decrypt(byte[] data, string key)
            {
                return MethodData(data, key, false);
            }

            public ItemEncryptationData Clon()
            {
                return new ItemEncryptationData(MethodData, MethodLenghtEncrypted, MethodLenghtDecrypted, LengthVariable);
            }
        }
        public class ItemEncryptationPassword : IClonable<ItemEncryptationPassword>
        {
            public delegate string MethodEncryptNonReversible(string password);
            public MethodEncryptNonReversible MethodPassword { get; set; }
            public bool LengthVariable;
            public ItemEncryptationPassword(MethodEncryptNonReversible methodPassword, bool lengthVariable)
            {
                MethodPassword = methodPassword;
                LengthVariable = lengthVariable;

            }
            public string Encrypt(string key)
            {
                return MethodPassword(key);
            }

            public ItemEncryptationPassword Clon()
            {
                return new ItemEncryptationPassword(MethodPassword, LengthVariable);
            }
        }
        /// <summary>
        /// Añadir el evento en todos los lugares donde haga referencia para así poder liberar memoria
        /// </summary>
        public event EventHandler DisposeKey;
        public Key(IdUnico id = null)
        {
            if (id == null)
                id = new IdUnico();

            Id = id;
            ItemsKey = new Llista<ItemKey>();
            ItemsEncryptData = new Llista<ItemEncryptationData>();
            ItemsEncryptPassword = new Llista<ItemEncryptationPassword>();
        }
        public Key(IList<ItemKey> itemsKey, IdUnico id = null)
            : this(id)
        {
            ItemsKey.AddRange(itemsKey);
        }
        ~Key()
        {
            Dispose();
            ItemsKey = null;
            ItemsEncryptData = null;
            ItemsEncryptPassword = null;
            Id = null;
            if (DisposeKey != null)
                DisposeKey(this, new EventArgs());

        }

        public Llista<ItemKey> ItemsKey { get; private set; }

        public Llista<ItemEncryptationData> ItemsEncryptData { get; private set; }
        public Llista<ItemEncryptationPassword> ItemsEncryptPassword { get; private set; }

        public IdUnico Id { get; private set; }

        public byte[] Encrypt(byte[] data)
        {
            ItemEncryptationData itemEncryptData;
            ItemEncryptationPassword itemEncryptPassword = null;
            for (int i = 0, f = ItemsKey.Count; i < f; i++)
            {
                itemEncryptData = ItemsEncryptData[ItemsKey[i].MethodData];
                if (ItemsEncryptPassword.Count > 0)
                    itemEncryptPassword = ItemsEncryptPassword[ItemsKey[i].MethodPassword];

                data = itemEncryptData.Encrypt(data, itemEncryptPassword.Encrypt(ItemsKey[i].Password) ?? ItemsKey[i].Password);
            }
            return data;
        }
        public string Encrypt(string data)
        {
            return Serializar.ToString(Encrypt(Serializar.GetBytes(data)));
        }
        public void Encrypt(FileInfo fileToEncrypt, string pathFileOut, int bufferLength = 100 * 1024)
        {
            BinaryReader brIn = null;
            BinaryWriter bwOut = null;
            FileStream fsOut = null;
            FileStream fsIn = null;
            byte[] buffer;

            if (File.Exists(pathFileOut))
                File.Delete(pathFileOut);
            try
            {
                fsIn = fileToEncrypt.GetStream();
                brIn = new BinaryReader(fsIn);
                fsOut = new FileStream(pathFileOut, FileMode.Create);
                bwOut = new BinaryWriter(fsOut);

                do
                {
                    if(brIn.BaseStream.Position>bufferLength)
                        buffer = brIn.ReadBytes(bufferLength);
                    else
                        buffer = brIn.ReadBytes((int)(brIn.BaseStream.Length- brIn.BaseStream.Position));

                    bwOut.Write(buffer.Length);
                    bwOut.Write(Encrypt(buffer));

                } while (!brIn.BaseStream.EndOfStream());

            }
            catch { throw; }
            finally
            {
                if (brIn != null)
                    brIn.Close();
                if (fsIn != null)
                    fsIn.Close();
                if (bwOut != null)
                    bwOut.Close();
                if (fsOut != null)
                    fsOut.Close();
            }
        }
        public FileInfo Encrypt(FileInfo fileToEncrypt, int bufferLength = 100 * 1024)
        {
            string pathFileEncrypted = System.IO.Path.Combine(fileToEncrypt.Directory.FullName, Path.GetFileNameWithoutExtension(fileToEncrypt.Name) + " encrypted_" + DateTime.Now.Ticks + "" + MiRandom.Next(int.MaxValue) + fileToEncrypt.Extension);
            Encrypt(fileToEncrypt, pathFileEncrypted, bufferLength);
            return new FileInfo(pathFileEncrypted);
        }
        /// <summary>
        /// Cifra de forma irreversible una clave
        /// </summary>
        /// <param name="keyToEncrypt"></param>
        /// <returns></returns>
        public Key Encrypt(Key keyToEncrypt, bool siempreGenerarLaMisma = false)
        {
            Key keyEncrypted = keyToEncrypt.Clon(siempreGenerarLaMisma);
            for (int i = 0; i < keyToEncrypt.ItemsKey.Count; i++)//si tiene algun disimulat puede variar las contraseñas es por eso que si se quiere generar la misma debe ser quitado en el clon :)
                keyEncrypted.ItemsKey[i].Password = keyToEncrypt.Encrypt(keyEncrypted.ItemsKey[i].Password).Substring(0, keyEncrypted.ItemsKey[i].Password.Length);
            return keyEncrypted;
        }
        public byte[] Decrypt(byte[] data)
        {
            ItemEncryptationData itemEncryptData;
            ItemEncryptationPassword itemEncryptPassword = null;
            for (int i = ItemsKey.Count - 1; i >= 0; i--)
            {

                itemEncryptData = ItemsEncryptData[ItemsKey[i].MethodData];
                if (ItemsEncryptPassword.Count > 0)
                    itemEncryptPassword = ItemsEncryptPassword[ItemsKey[i].MethodPassword];

                data = itemEncryptData.Decrypt(data, itemEncryptPassword.Encrypt(ItemsKey[i].Password) ?? ItemsKey[i].Password);
            }
            return data;
        }
        public string Decrypt(string data)
        {
            return Serializar.ToString(Decrypt(Serializar.GetBytes(data)));
        }

        public void Decrypt(FileInfo fileToDecrypt, string pathFileOut)
        {
            BinaryReader brIn = null;
            BinaryWriter bwOut = null;
            FileStream fsOut = null;
            FileStream fsIn = null;


            if (File.Exists(pathFileOut))
                File.Delete(pathFileOut);
            try
            {
                fsIn = fileToDecrypt.GetStream();
                brIn = new BinaryReader(fsIn);
                fsOut = new FileStream(pathFileOut, FileMode.Create);
                bwOut = new BinaryWriter(fsOut);

                do
                {
                    bwOut.Write(Decrypt(brIn.ReadBytes(brIn.ReadInt32())));

                } while (!brIn.BaseStream.EndOfStream());

            }
            catch { throw; }
            finally
            {
                if (brIn != null)
                    brIn.Close();
                if (fsIn != null)
                    fsIn.Close();
                if (bwOut != null)
                    bwOut.Close();
                if (fsOut != null)
                    fsOut.Close();
            }
        }
        public FileInfo Decrypt(FileInfo fileToEncrypt)
        {
            string pathFileEncrypted = System.IO.Path.Combine(fileToEncrypt.Directory.FullName, Path.GetFileNameWithoutExtension(fileToEncrypt.Name) + " decrypted_" + DateTime.Now.Ticks + "" + MiRandom.Next(int.MaxValue) + fileToEncrypt.Extension);
            Decrypt(fileToEncrypt, pathFileEncrypted);
            return new FileInfo(pathFileEncrypted);
        }
        public int LengthEncrypt(int lengthDecrypt)
        {
            int lenghtEncrypt;
            lenghtEncrypt = ItemsEncryptData[ItemsKey[0].MethodData].MethodLenghtEncrypted(lengthDecrypt);
            for (int i = 1; i < ItemsKey.Count; i++)
            {
                lenghtEncrypt += ItemsEncryptData[ItemsKey[i].MethodData].MethodLenghtEncrypted(lenghtEncrypt);
            }
            return lenghtEncrypt;
        }
        public int LengthDecrypt(int lengthEncrypt)
        {
            int lengthDecrypt;
            lengthDecrypt = ItemsEncryptData[ItemsKey[0].MethodData].MethodLenghtDecrypted(lengthEncrypt);
            for (int i = 1; i < ItemsKey.Count; i++)
            {
                lengthDecrypt -= ItemsEncryptData[ItemsKey[i].MethodData].MethodLenghtDecrypted(lengthDecrypt);
            }
            return lengthDecrypt;
        }

        public Key Clon(bool deleteTamañoVariable)
        {
            Key key = new Key();
            bool[] encryptData = new bool[ItemsEncryptData.Count];
            bool[] encryptPassword = new bool[ItemsEncryptPassword.Count];

            for (int i = 0; i < ItemsEncryptData.Count; i++)
            {
                encryptData[i] = ItemsEncryptData[i].LengthVariable;
                if (!deleteTamañoVariable || !encryptData[i])
                    key.ItemsEncryptData.Add(ItemsEncryptData[i].Clon());
            }
            for (int i = 0; i < ItemsEncryptPassword.Count; i++)
            {
                encryptPassword[i] = ItemsEncryptPassword[i].LengthVariable;
                if (!deleteTamañoVariable || !encryptPassword[i])
                    key.ItemsEncryptPassword.Add(ItemsEncryptPassword[i].Clon());
            }
            for (int i = 0; i < ItemsKey.Count; i++)
            {
                if (!deleteTamañoVariable || !encryptData[ItemsKey[i].MethodData] && !encryptPassword[ItemsKey[i].MethodPassword])
                    key.ItemsKey.Add(ItemsKey[i].Clon());
            }
            return key;

        }
        public Key Clon() => Clon(false);

        public override bool Equals(object obj)
        {
            return Equals(obj as Key);
        }
        public bool Equals(Key other)
        {
            bool equals = other != null && ItemsKey.Count == other.ItemsKey.Count;
            for (int i = 0; i < ItemsKey.Count && equals; i++)
                equals = ItemsKey[i].Equals(other.ItemsKey[i]);
            return equals;
        }

        void IDisposable.Dispose()
        {

            Dispose();
        }
        void Dispose()
        {
            ItemsKey.Clear();
            ItemsEncryptData.Clear();
            ItemsEncryptPassword.Clear();
        }


        public static Key GetKey(long numeroDeRandomPasswords)
        {
            string[] randomPasswords = new string[numeroDeRandomPasswords];
            for (long i = 0; i < numeroDeRandomPasswords; i++)
            {
                randomPasswords[i] = (MiRandom.Next() + "").EncryptNotReverse(PasswordEncrypt.Md5);
            }
            return GetKey(randomPasswords);

        }
        public static Key GetKey(params string[] passwords)
        {
            return GetKey((IList<string>)passwords);
        }
        public static Key GetKey(IList<string> passwords)
        {
            const int CESAR = 0, PERDUT = 1;
            if (passwords == null)
                throw new ArgumentNullException();


            Key key = new Key();
            key.ItemsEncryptData.Add(new ItemEncryptationData(MetodoCesar, GetLenghtMetodosCifradoLongitudInvariable, GetLenghtMetodosCifradoLongitudInvariable, false));
            key.ItemsEncryptData.Add(new ItemEncryptationData(MetodoPerdut, GetLenghtMetodosCifradoLongitudInvariable, GetLenghtMetodosCifradoLongitudInvariable, false));
            key.ItemsEncryptPassword.Add(new ItemEncryptationPassword(MetodoHash, false));
            for (int i = 0; i < passwords.Count; i++)
            {
                if (!String.IsNullOrEmpty(passwords[i]))
                    key.ItemsKey.Add(new ItemKey(password: passwords[i]) { MethodData = CESAR });
            }
            if (passwords.Count != 0)
            {
                key.ItemsKey[0].MethodData = PERDUT;
                key.ItemsKey[key.ItemsKey.Count - 1].MethodData = PERDUT;
            }
            return key;
        }

        private static int GetLenghtMetodosCifradoLongitudInvariable(int lenght)
        {
            return lenght;
        }

        private static byte[] MetodoPerdut(byte[] data, string password, bool encrypt)
        {
            byte[] dataOut;
            if (encrypt)
            {
                dataOut = data.Encrypt(password, DataEncrypt.Perdut, LevelEncrypt.Highest);
            }
            else
            {
                dataOut = data.Decrypt(password, DataEncrypt.Perdut, LevelEncrypt.Highest);
            }
            return dataOut;
        }

        private static byte[] MetodoCesar(byte[] data, string password, bool encrypt)
        {
            byte[] dataOut;
            if (encrypt)
            {
                dataOut = data.Encrypt(password, DataEncrypt.Cesar, LevelEncrypt.Highest);
            }
            else
            {
                dataOut = data.Decrypt(password, DataEncrypt.Cesar, LevelEncrypt.Highest);
            }
            return dataOut;
        }

        private static string MetodoHash(string password)
        {
            return password.EncryptNotReverse();
        }


    }
}