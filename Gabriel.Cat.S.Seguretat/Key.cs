﻿using Gabriel.Cat.S.Extension;
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
            public ItemKey(int methodData = 0, int methodPassword = 0, string password = null) : this(methodData, methodPassword, password == null)
            {
                if (password != null)
                    Password = password;
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
            public delegate int MethodGetLenght(int lenght);

            public MethodEncryptReversible MethodData { get; set; }
            public MethodGetLenght MethodLenghtEncrypted { get; set; }
            public MethodGetLenght MethodLenghtDecrypted { get; set; }
            public ItemEncryptationData(MethodEncryptReversible methodData,MethodGetLenght methodGetLenghtEncrypted,MethodGetLenght methodGetLenghtDecrypted)
            {
                MethodData = methodData;
                MethodLenghtDecrypted = methodGetLenghtDecrypted;
                MethodLenghtEncrypted = methodGetLenghtEncrypted;

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
      

        Llista<ItemEncryptationData> itemsEncryptData;
        Llista<ItemEncryptationPassword> itemsEncryptPassword;
        Llista<ItemKey> itemsKey;
        IdUnico id;
        public Key(IdUnico id=null)
        {
            if (id == null)
                id = new IdUnico();

            this.Id = id;
            itemsKey = new Llista<ItemKey>();
            itemsEncryptData = new Llista<ItemEncryptationData>();
            itemsEncryptPassword = new Llista<ItemEncryptationPassword>();
        }
        public Key(IList<ItemKey> itemsKey, IdUnico id=null)
            : this(id)
        {
            ItemsKey.AddRange(itemsKey);
        }
    

        public Llista<ItemKey> ItemsKey
        {
            get { return itemsKey; }
        }

        public Llista<ItemEncryptationData> ItemsEncryptData
        {
            get
            {
                return itemsEncryptData;
            }
        }
        public Llista<ItemEncryptationPassword> ItemsEncryptPassword
        {
            get
            {
                return itemsEncryptPassword;
            }
        }

        public IdUnico Id { get => id; private set => id = value; }

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
        public int LengthEncrypt(int lengthDecrypt)
        {
            int lenghtEncrypt;
            lenghtEncrypt = itemsEncryptData[itemsKey[0].MethodData].MethodLenghtEncrypted(lengthDecrypt);
            for (int i = 1; i < itemsKey.Count; i++) {
                lenghtEncrypt += itemsEncryptData[itemsKey[i].MethodData].MethodLenghtEncrypted(lenghtEncrypt);
            }
            return lenghtEncrypt;
        }
        public int LengthDecrypt(int lengthEncrypt)
        {
            int lengthDecrypt;
            lengthDecrypt = itemsEncryptData[itemsKey[0].MethodData].MethodLenghtDecrypted(lengthEncrypt);
            for (int i = 1; i < itemsKey.Count; i++)
            {
                lengthDecrypt -= itemsEncryptData[itemsKey[i].MethodData].MethodLenghtDecrypted(lengthDecrypt);
            }
            return lengthDecrypt;
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
            key.ItemsEncryptData.Add(new ItemEncryptationData(MetodoCesar,GetLenghtMetodosCifradoLongitudInvariable,GetLenghtMetodosCifradoLongitudInvariable));
            key.ItemsEncryptData.Add(new ItemEncryptationData(MetodoPerdut, GetLenghtMetodosCifradoLongitudInvariable, GetLenghtMetodosCifradoLongitudInvariable));
            key.ItemsEncryptPassword.Add(new ItemEncryptationPassword(MetodoHash));
            for (int i = 0; i < passwords.Count; i++)
            {
                if (!String.IsNullOrEmpty(passwords[i]))
                    key.ItemsKey.Add(new ItemKey(password:passwords[i]) { MethodData = CESAR });
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