using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml.Linq;

namespace Gabriel.Cat.S.Seguretat
{
    public class Key
    {
     
        public class ItemKey
        {


            public int MethodData { get; set; }
            public int MethodPassword { get; set; }
            public string Password { get; set; }
            public ItemKey(int methodData = 0, int methodPassword = 0, bool randomKey = true, int lenghtRandomKey = 15)
            {
                MethodData = methodData;
                MethodPassword = methodPassword;
                if (!randomKey)
                    Password = "";
                else
                    GenerateRandomKey(lenghtRandomKey);
            }
         
       
            public void GenerateRandomKey(int lenght = 15)
            {
                if (lenght < 0)
                    throw new ArgumentOutOfRangeException();
                StringBuilder str = new StringBuilder();
                for (int i = 0; i < lenght; i++)
                    str.Append((char)MiRandom.Next(256));

                Password = str.ToString();
            }


        }
        public class ItemEncryptationData
        {
            public delegate byte[] MethodEncryptReversible(byte[] data, string password, bool encrypt = true);


            public MethodEncryptReversible MethodData { get; set; }

            public ItemEncryptationData(MethodEncryptReversible methodData)
            {
                MethodData = methodData;

            }
            public byte[] Encrypt(byte[] data, string key)
            {
                return MethodData(data, key);
            }
            public byte[] Decrypt(byte[] data, string key)
            {
                return MethodData(data, key, false);
            }
        }
        public class ItemEncryptationPassword
        {
            public delegate string MethodEncryptNonReversible(string password);
            public MethodEncryptNonReversible MethodPassword { get; set; }

            public ItemEncryptationPassword(MethodEncryptNonReversible methodPassword)
            {
                MethodPassword = methodPassword;

            }
            public string Encrypt(string key)
            {
                return MethodPassword(key);
            }
        }
      

        List<ItemEncryptationData> itemsEncryptData;
        List<ItemEncryptationPassword> itemsEncryptPassword;
        List<ItemKey> itemsKey;
        public Key()
        {
            itemsKey = new List<ItemKey>();
            itemsEncryptData = new List<ItemEncryptationData>();
            itemsEncryptPassword = new List<ItemEncryptationPassword>();
        }
        public Key(IEnumerable<ItemKey> itemsKey)
            : this()
        {
            ItemsKey.AddRange(itemsKey);
        }
    

        public List<ItemKey> ItemsKey
        {
            get { return itemsKey; }
        }

        public List<ItemEncryptationData> ItemsEncryptData
        {
            get
            {
                return itemsEncryptData;
            }
        }
        public List<ItemEncryptationPassword> ItemsEncryptPassword
        {
            get
            {
                return itemsEncryptPassword;
            }
        }
        public byte[] Encrypt(byte[] data)
        {
            ItemEncryptationData itemEncryptData;
            ItemEncryptationPassword itemEncryptPassword = null;
            for (int i = 0, f = itemsKey.Count; i < f; i++)
            {
                itemEncryptData = itemsEncryptData[itemsKey[i].MethodData];
                if (itemsEncryptPassword.Count > 0)
                    itemEncryptPassword = itemsEncryptPassword[itemsKey[i].MethodPassword];

                data = itemEncryptData.Encrypt(data, itemEncryptPassword.Encrypt(itemsKey[i].Password) ?? itemsKey[i].Password);
            }
            return data;
        }
        public string Encrypt(string data)
        {
            return Serializar.ToString(Encrypt(Serializar.GetBytes(data)));
        }
        public byte[] Decrypt(byte[] data)
        {
            ItemEncryptationData itemEncryptData;
            ItemEncryptationPassword itemEncryptPassword = null;
            for (int i = itemsKey.Count - 1; i >= 0; i--)
            {

                itemEncryptData = itemsEncryptData[itemsKey[i].MethodData];
                if (itemsEncryptPassword.Count > 0)
                    itemEncryptPassword = itemsEncryptPassword[itemsKey[i].MethodPassword];

                data = itemEncryptData.Decrypt(data, itemEncryptPassword.Encrypt(itemsKey[i].Password) ?? itemsKey[i].Password);
            }
            return data;
        }
        public string Decrypt(string data)
        {
            return Serializar.ToString(Decrypt(Serializar.GetBytes(data)));
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
            key.ItemsEncryptData.Add(new ItemEncryptationData(MetodoCesar));
            key.ItemsEncryptData.Add(new ItemEncryptationData(MetodoPerdut));
            key.ItemsEncryptPassword.Add(new ItemEncryptationPassword(MetodoHash));
            for (int i = 0; i < passwords.Count; i++)
            {
                if (!String.IsNullOrEmpty(passwords[i]))
                    key.ItemsKey.Add(new ItemKey() { Password = passwords[i], MethodData = CESAR });
            }
            if (passwords.Count != 0)
            {
                key.ItemsKey[0].MethodData = PERDUT;
                key.ItemsKey[key.ItemsKey.Count - 1].MethodData = PERDUT;
            }
            return key;
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