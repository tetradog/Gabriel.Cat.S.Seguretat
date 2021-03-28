using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.Drawing;
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
                if (randomKey)
                    GenerateRandomKey(lenghtRandomKey);
            }
            public ItemKey(int methodData = 0, int methodPassword = 0, byte[] password = default) : this(methodData, methodPassword, Equals(password, default))
            {
                if (!Equals(password,default))
                    Password = password;
            }
              public ItemKey(int methodData = 0, int methodPassword = 0, string password = default) : this(methodData, methodPassword, Equals(password, default))
            {
                if (!Equals(password, default))
                    Password =Serializar.GetBytes(password);
            }
            public int MethodData { get; set; }
            public int MethodPassword { get; set; }
            public byte[] Password { get; set; }

            public void GenerateRandomKey(int lenght = 15)
            {
                if (lenght < 0)
                    throw new ArgumentOutOfRangeException();



                Password = MiRandom.NextBytes(lenght);
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
                return !Equals(other,default) && Password.Equals(other.Password) && MethodData == other.MethodData && MethodPassword.Equals(other.MethodPassword);
            }
        }


        public class ItemEncryptationData : IClonable<ItemEncryptationData>
        {
            public delegate byte[] MethodEncryptReversible(byte[] data, byte[] password, bool encrypt = true,LevelEncrypt levelEncrypt=LevelEncrypt.Normal);
            public delegate int MethodGetLenght(int lenght,LevelEncrypt levelEncrypt=LevelEncrypt.Normal);

            public MethodEncryptReversible MethodData { get; set; }
            public MethodGetLenght MethodLenghtEncrypted { get; set; }
            public MethodGetLenght MethodLenghtDecrypted { get; set; }
            public bool LengthVariable{get;set;}
            public ItemEncryptationData(MethodEncryptReversible methodData, MethodGetLenght methodGetLenghtEncrypted, MethodGetLenght methodGetLenghtDecrypted, bool lenghtVariable)
            {
                MethodData = methodData;
                MethodLenghtDecrypted = methodGetLenghtDecrypted;
                MethodLenghtEncrypted = methodGetLenghtEncrypted;
                LengthVariable = lenghtVariable;
            }
            public byte[] Encrypt(byte[] data, byte[] key,LevelEncrypt levelEncrypt)
            {
                return MethodData(data, key,true,levelEncrypt);
            }
            public byte[] Decrypt(byte[] data, byte[] key, LevelEncrypt levelEncrypt)
            {
                return MethodData(data, key, false,levelEncrypt);
            }

            public ItemEncryptationData Clon()
            {
                return new ItemEncryptationData(MethodData, MethodLenghtEncrypted, MethodLenghtDecrypted, LengthVariable);
            }
        }
        public class ItemEncryptationPassword : IClonable<ItemEncryptationPassword>
        {
            public delegate byte[] MethodEncryptNonReversible(byte[] password);
            public MethodEncryptNonReversible MethodPassword { get; set; }
            public bool LengthVariable{get;set;}
            public ItemEncryptationPassword(MethodEncryptNonReversible methodPassword, bool lengthVariable)
            {
                MethodPassword = methodPassword;
                LengthVariable = lengthVariable;

            }
            public byte[] Encrypt(byte[] key)
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
        public Key(IList<ItemKey> itemsKey,bool initDefaultMethods=true, IdUnico id = null)
            : this(id)
        {
            if(initDefaultMethods)
               InitMethods();

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
        private void InitMethods()
        {
            ItemsEncryptData.Add(new ItemEncryptationData(MetodoCesar, GetLenghtMetodosCifradoLongitudInvariable, GetLenghtMetodosCifradoLongitudInvariable, false));
         //todavia no funciona //  ItemsEncryptData.Add(new ItemEncryptationData(MetodoOldLost, GetLenghtMetodosCifradoLongitudInvariable, GetLenghtMetodosCifradoLongitudInvariable, false));
            ItemsEncryptData.Add(new ItemEncryptationData(MetodoPerdut, GetLenghtMetodosCifradoLongitudInvariable, GetLenghtMetodosCifradoLongitudInvariable, false));
            ItemsEncryptPassword.Add(new ItemEncryptationPassword(MetodoHash, false));
        }
        public byte[] Encrypt(byte[] data,LevelEncrypt levelEncrypt=LevelEncrypt.Normal)
        {
            ItemEncryptationData itemEncryptData;
            ItemEncryptationPassword itemEncryptPassword = null;
            for (int i = 0, f = ItemsKey.Count; i < f; i++)
            {
                itemEncryptData = ItemsEncryptData[ItemsKey[i].MethodData];
                if (ItemsEncryptPassword.Count > 0)
                    itemEncryptPassword = ItemsEncryptPassword[ItemsKey[i].MethodPassword];

                data = itemEncryptData.Encrypt(data, itemEncryptPassword.Encrypt(ItemsKey[i].Password) ?? ItemsKey[i].Password,levelEncrypt);
            }
            return data;
        }
        public string Encrypt(string data,LevelEncrypt levelEncrypt=LevelEncrypt.Normal)
        {
            return Serializar.ToString(Encrypt(Serializar.GetBytes(data),levelEncrypt));
        }
        public IList<Bitmap> Encrypt(byte[] data,IList<Bitmap> outputBmps,LevelEncrypt levelEncryptData=LevelEncrypt.Normal,LevelEncrypt levelEncryptImage=LevelEncrypt.Normal)
        {
            return outputBmps.SetData(Encrypt(data,levelEncryptData),levelEncryptImage);
        }
        public IList<Bitmap> Encrypt(string data, IList<Bitmap> outputBmps,LevelEncrypt levelEncryptData=LevelEncrypt.Normal,LevelEncrypt levelEncryptImage=LevelEncrypt.Normal)
        {
            return outputBmps.SetData(Encrypt(Serializar.GetBytes(data),levelEncryptData), levelEncryptImage);
        }
  
        public void Encrypt(FileInfo fileToEncrypt, string pathFileOut,LevelEncrypt levelEncrypt=LevelEncrypt.Normal, int bufferLength = 100 * 1024)
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
                    bwOut.Write(Encrypt(buffer,levelEncrypt));

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
        public FileInfo Encrypt(FileInfo fileToEncrypt,LevelEncrypt levelEncryptData=LevelEncrypt.Normal, int bufferLength = 100 * 1024)
        {
            string pathFileEncrypted = System.IO.Path.Combine(fileToEncrypt.Directory.FullName, Path.GetFileNameWithoutExtension(fileToEncrypt.Name) + " encrypted_" + DateTime.Now.Ticks + "" + MiRandom.Next(int.MaxValue) + fileToEncrypt.Extension);
            Encrypt(fileToEncrypt, pathFileEncrypted, levelEncryptData, bufferLength);
            return new FileInfo(pathFileEncrypted);
        }
        /// <summary>
        /// Cifra de forma irreversible una clave
        /// </summary>
        /// <param name="keyToEncrypt"></param>
        /// <returns></returns>
        public Key Encrypt(Key keyToEncrypt,LevelEncrypt levelEncryptData=LevelEncrypt.Normal, bool siempreGenerarLaMisma = false)
        {
            Key keyEncrypted = keyToEncrypt.Clon(siempreGenerarLaMisma);
            for (int i = 0; i < keyToEncrypt.ItemsKey.Count; i++)//si tiene algun disimulat puede variar las contraseñas es por eso que si se quiere generar la misma debe ser quitado en el clon :)
                keyEncrypted.ItemsKey[i].Password = keyToEncrypt.Encrypt(keyEncrypted.ItemsKey[i].Password, levelEncryptData).SubArray(0, keyEncrypted.ItemsKey[i].Password.Length);
            return keyEncrypted;
        }
        public byte[] Decrypt(byte[] data,LevelEncrypt levelEncryptData=LevelEncrypt.Normal)
        {
            ItemEncryptationData itemEncryptData;
            ItemEncryptationPassword itemEncryptPassword = null;
            for (int i = ItemsKey.Count - 1; i >= 0; i--)
            {

                itemEncryptData = ItemsEncryptData[ItemsKey[i].MethodData];
                if (ItemsEncryptPassword.Count > 0)
                    itemEncryptPassword = ItemsEncryptPassword[ItemsKey[i].MethodPassword];

                data = itemEncryptData.Decrypt(data, itemEncryptPassword.Encrypt(ItemsKey[i].Password) ?? ItemsKey[i].Password,levelEncryptData);
            }
            return data;
        }
        public byte[] Decrypt(IList<Bitmap> outputBmps,LevelEncrypt levelEncryptData=LevelEncrypt.Normal,LevelEncrypt levelEncryptImage=LevelEncrypt.Normal)
        {
            return Decrypt(outputBmps.GetData(levelEncryptImage),levelEncryptData);
        }
        public string Decrypt(string data,LevelEncrypt levelEncryptData=LevelEncrypt.Normal)
        {
            return Serializar.ToString(Decrypt(Serializar.GetBytes(data),levelEncryptData));
        }

        public void Decrypt(FileInfo fileToDecrypt, string pathFileOut,LevelEncrypt levelEncryptData=LevelEncrypt.Normal)
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
                    bwOut.Write(Decrypt(brIn.ReadBytes(brIn.ReadInt32()),levelEncryptData));

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
        public FileInfo Decrypt(FileInfo fileToEncrypt,LevelEncrypt levelEncryptData=LevelEncrypt.Normal)
        {
            string pathFileEncrypted = System.IO.Path.Combine(fileToEncrypt.Directory.FullName, Path.GetFileNameWithoutExtension(fileToEncrypt.Name) + " decrypted_" + DateTime.Now.Ticks + "" + MiRandom.Next(int.MaxValue) + fileToEncrypt.Extension);
            Decrypt(fileToEncrypt, pathFileEncrypted,levelEncryptData);
            return new FileInfo(pathFileEncrypted);
        }
        public int LengthEncrypt(int lengthDecrypt,LevelEncrypt levelEncryptData=LevelEncrypt.Normal)
        {
            int lenghtEncrypt;
            lenghtEncrypt = ItemsEncryptData[ItemsKey[0].MethodData].MethodLenghtEncrypted(lengthDecrypt,levelEncryptData);
            for (int i = 1; i < ItemsKey.Count; i++)
            {
                lenghtEncrypt += ItemsEncryptData[ItemsKey[i].MethodData].MethodLenghtEncrypted(lenghtEncrypt,levelEncryptData);
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


        public static Key GetKey(long numeroDeRandomPasswords,int lengthPassword=15*2)
        {
            byte[][] randomPasswords = new byte[numeroDeRandomPasswords][];
            for (long i = 0; i < numeroDeRandomPasswords; i++)
            {
                randomPasswords[i] = MiRandom.NextBytes(lengthPassword);
            }
            return GetKey(randomPasswords);

        }
        public static Key GetKey(params byte[][] passwords)
        {
            return GetKey((IList<byte[]>)passwords);
        }
        public static Key GetKey(IList<byte[]> passwords)
        {
            const int CESAR = 0, PERDUT = 1;//,OLDLOST=2;
            if (passwords == null)
                throw new ArgumentNullException();


            Key key = new Key();
            key.InitMethods();
            for (int i = 0; i < passwords.Count; i++)
            {
                if (passwords[i].Length==0)
                    key.ItemsKey.Add(new ItemKey(password: passwords[i]) { MethodData = CESAR });
            }
            if (passwords.Count != 0)
            {
                key.ItemsKey[0].MethodData = PERDUT;
                //   key.ItemsKey[key.ItemsKey.Count - 1].MethodData = OLDLOST;
                key.ItemsKey[key.ItemsKey.Count - 1].MethodData = PERDUT;
            }
            return key;
        }


        private static int GetLenghtMetodosCifradoLongitudInvariable(int lenght,LevelEncrypt levelEncrypt=LevelEncrypt.Normal)
        {
            return lenght;
        }
        private static byte[] MetodoOldLost(byte[] data, byte[] password, bool encrypt,LevelEncrypt levelEncrypt)
        {
            return MetodoComun(data, password, encrypt, DataEncrypt.OldLost,levelEncrypt);
        }
        private static byte[] MetodoPerdut(byte[] data, byte[] password, bool encrypt,LevelEncrypt levelEncrypt)
        {
            return MetodoComun(data, password, encrypt, DataEncrypt.Perdut,levelEncrypt);
        }

        private static byte[] MetodoCesar(byte[] data, byte[] password, bool encrypt,LevelEncrypt levelEncrypt)
        {
            return MetodoComun(data, password, encrypt, DataEncrypt.Cesar,levelEncrypt);
        }

        private static byte[] MetodoHash(byte[] password)
        {
            return password.EncryptNotReverse();
        }

        static byte[] MetodoComun(byte[] data, byte[] password, bool encrypt, DataEncrypt metodo,LevelEncrypt levelEncrypt)
        {
            byte[] result;
            if (encrypt)
            {
                result = data.Encrypt(password, metodo, levelEncrypt);
            }
            else
            {
                result = data.Decrypt(password, metodo, levelEncrypt);

            }
            return result;
        }


    }
}
