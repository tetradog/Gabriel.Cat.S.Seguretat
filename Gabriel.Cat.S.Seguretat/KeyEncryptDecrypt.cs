using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    public class CrazyKey
    {
        public class CrazyItem{
            

            public CrazyItem()
            {
                //Random
                GenKey = 0;
                MethodEncryptDataMethods = 0;
                MethodEncryptPasswordMethods = 0;
            }
            public byte GenKey
            { get; set; }
            public byte MethodEncryptDataMethods { get; set; }
            public byte MethodEncryptPasswordMethods { get; set; }
            //public CrazyItem(args) para restaurarlo
            public void Encrypt(SortedList<byte,Key> dicKeys,Key keyToEncrypt)
            {
                const int GENINICIAL = byte.MinValue;

                int[] dataMethods;
                int[] passwordsMethods;
 
                if (!dicKeys.ContainsKey(GenKey))
                {
                    for (byte genActual = 1,genAnterior=0; genActual < GenKey; genActual++,genAnterior++)
                    {
                        if (!dicKeys.ContainsKey(genActual))
                            dicKeys.Add(genActual, dicKeys[genAnterior].Encrypt(dicKeys[GENINICIAL]));
                    }
                }

                dataMethods = new int[keyToEncrypt.ItemsKey.Count];
                passwordsMethods = new int[keyToEncrypt.ItemsKey.Count];
              
                for(int i=0;i<keyToEncrypt.ItemsKey.Count;i++)
                {
                    dataMethods[i] = keyToEncrypt.ItemsKey[i].MethodData;
                    passwordsMethods[i] = keyToEncrypt.ItemsKey[i].MethodPassword;
                }
                //trato las arrays cifro

                for (int i = 0; i < keyToEncrypt.ItemsKey.Count; i++)
                {
                    keyToEncrypt.ItemsKey[i].MethodData = dataMethods[i] ;
                    keyToEncrypt.ItemsKey[i].MethodPassword = passwordsMethods[i];
                    keyToEncrypt.ItemsKey[i].Password = dicKeys[GenKey].Encrypt(keyToEncrypt.ItemsKey[i].Password).Substring(0, keyToEncrypt.ItemsKey[i].Password.Length);
                }

            }

        }


        public List<CrazyItem> CrazyItems { get; private set; }

        public CrazyKey(int randomItems):this()
        {
           
            RandomItems(randomItems);
        }
        public CrazyKey()
        { CrazyItems = new List<CrazyItem>(); }
        public void RandomItems(int random)
        {
            if (random < 1)
                throw new ArgumentOutOfRangeException("tiene que tener mínimo 1");

            CrazyItems.Clear();

            for (int i = 0; i < random; i++)
                CrazyItems.Add(new CrazyItem());
        }
        /// <summary>
        /// Encrypta una Key de forma irreversible y obtiene otra como resultado
        /// </summary>
        /// <param name="keyToEncrypt"></param>
        /// <returns></returns>
        public Key Encrypt(Key keyToEncrypt)
        {
            Key keyEncrypted = keyToEncrypt.Clon();
            SortedList<byte, Key> dicKeys = new SortedList<byte, Key>();

            dicKeys.Add(byte.MinValue, keyToEncrypt);

            for (int i = 0; i < CrazyItems.Count; i++)
                CrazyItems[i].Encrypt(dicKeys,keyEncrypted);

            return keyEncrypted;
        }

    }
}
