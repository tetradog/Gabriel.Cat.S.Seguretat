using Gabriel.Cat.S.Utilitats;
using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    public class CrazyKey
    {
        public class CrazyItem
        {
           
            public enum MetodoEncrypt
            {
                Cesar,Perdut
            }
            static LlistaOrdenada<IdUnico, SortedList<byte, Key>> dicKeysGen;
            static readonly int MetodosEncryptLength;
            static CrazyItem()
            {
                MetodosEncryptLength = Enum.GetNames(typeof(MetodoEncrypt)).Length;
                dicKeysGen = new LlistaOrdenada<IdUnico, SortedList<byte, Key>>();
            }
            public CrazyItem()
            {
                //Random
                GenKey = (byte)MiRandom.Next(7); 
                DataMethods =(MetodoEncrypt) MiRandom.Next(0,MetodosEncryptLength);
                PasswordMethods = (MetodoEncrypt)MiRandom.Next(0, MetodosEncryptLength);
            }
            public byte GenKey
            { get; set; }
            public MetodoEncrypt DataMethods { get; set; }
            public MetodoEncrypt PasswordMethods { get; set; }
            //public CrazyItem(args) para restaurarlo
            public void Encrypt(Key keyOrigen,Key keyToEncrypt)
            {//tengo un dilema por el uso de memoria ram...se podria ir vaciando cada x tiempo...aunque si borro las frecuentes y estas encima son pesadas...
                const byte GENINICIAL = byte.MinValue;
                const int MAXARRAYENCRYPT = 100;
                int[] dataMethods;
                int[] passwordsMethods;
                Key keyCifrarPassword;

                AddKeyOrigen(keyOrigen);

                if (!dicKeysGen[keyOrigen.Id].ContainsKey(GenKey))
                {
                    for (byte genActual = 1, genAnterior = GENINICIAL; genActual <= GenKey; genActual++, genAnterior++)
                    {
                        if (!dicKeysGen[keyOrigen.Id].ContainsKey(genActual))
                            dicKeysGen[keyOrigen.Id].Add(genActual, dicKeysGen[keyOrigen.Id][genAnterior].Encrypt(dicKeysGen[keyOrigen.Id][GENINICIAL]));
                    }
                }

                dataMethods = new int[keyToEncrypt.ItemsKey.Count];
                passwordsMethods = new int[keyToEncrypt.ItemsKey.Count];

                for (int i = 0; i < keyToEncrypt.ItemsKey.Count; i++)
                {
                    dataMethods[i] = keyToEncrypt.ItemsKey[i].MethodData;
                    passwordsMethods[i] = keyToEncrypt.ItemsKey[i].MethodPassword;
                }

                for (int i = 0; i < keyToEncrypt.ItemsKey.Count&&i<MAXARRAYENCRYPT; i++)
                {
                    //trato las arrays cifro uso las contraseñas solo para usar los metodos Perdut y Cesar
                    TrataArray(dataMethods, keyToEncrypt.ItemsKey[i].Password, DataMethods);
                    TrataArray(passwordsMethods, keyToEncrypt.ItemsKey[i].Password, PasswordMethods);
                }

                keyCifrarPassword = dicKeysGen[keyOrigen.Id][GenKey];

                for (int i = 0; i < keyToEncrypt.ItemsKey.Count; i++)
                {
                    keyToEncrypt.ItemsKey[i].MethodData = dataMethods[i];
                    keyToEncrypt.ItemsKey[i].MethodPassword = passwordsMethods[i];
                    keyToEncrypt.ItemsKey[i].Password = keyCifrarPassword.Encrypt(keyToEncrypt.ItemsKey[i].Password);//siempre deben dar lo mismo sino crearia problemas.
                }

            }
            static void TrataArray(int[] array,string password,MetodoEncrypt metodo)
            {


                byte[] passwordBytes = Gabriel.Cat.S.Utilitats.Serializar.GetBytes(password);
                switch(metodo)
                {
                    case MetodoEncrypt.Cesar:CesarArray(array, passwordBytes);break;
                    case MetodoEncrypt.Perdut: PierdeArray(array, passwordBytes); break;
                }
            }
            static void PierdeArray(int[] array, byte[] password)
            {
                int aux;
                long posAux;

                unsafe
                {
                    fixed (int* ptrArray = array)
                    {
                        int* ptArray = ptrArray;//creo que optmizo un poquito al no entrar en la propiedad :D
                        for (long i = 0, f = array.Length - 1; i <= f; i++)
                        {
                            posAux = (EncryptDecrypt.CalculoNumeroCifrado(password, LevelEncrypt.Normal, Utilitats.Ordre.ConsecutiuIAlInreves, i) + i) % array.Length;
                            aux = ptArray[posAux];
                            ptArray[posAux] = ptArray[i];
                            ptArray[i] = aux;
                        }
                    }
                }

            }
            static void CesarArray(int[] array, byte[] password)
            {

                int sumaCesar;
                unsafe
                {
                    int* ptrBytesOri;
                    fixed (int* ptrArray = array)
                    {

                        ptrBytesOri = ptrArray;

                        for (long i = 0, pos = 0; i < array.Length; i++, pos++)
                        {
                            sumaCesar = EncryptDecrypt.CalculoNumeroCifrado(password, LevelEncrypt.Normal, Utilitats.Ordre.ConsecutiuIAlInreves, pos);
                            *ptrBytesOri = (*ptrBytesOri + sumaCesar) % (MetodosEncryptLength + 1);
                            ptrBytesOri++;
                        }

                    }
                }

            }
            internal static void AddKeyOrigen(Key key)
            {
                if (!dicKeysGen.ContainsKey(key.Id))
                {
                    dicKeysGen.Add(key.Id, new SortedList<byte, Key>());
                    if (!dicKeysGen[key.Id].ContainsKey(byte.MinValue))
                        dicKeysGen[key.Id].Add(byte.MinValue, key);
                    //asi puedo liberar memoria :)
                    key.DisposeKey += (s, m) => dicKeysGen.Remove(((Key)s).Id);
                }
            }
        }


       

        public CrazyKey(int randomItems) : this()
        {

            RandomItems(randomItems);
        }
        public CrazyKey()
        { CrazyItems = new List<CrazyItem>(); }

        public List<CrazyItem> CrazyItems { get; private set; }

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
            Key keyEncrypted = keyToEncrypt.Clon(false);

            for (int i = 0; i < CrazyItems.Count; i++)
                CrazyItems[i].Encrypt(keyToEncrypt,keyEncrypted);

            return keyEncrypted;
        }

    }
}
