using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    public class CrazyKey
    {
        public class CrazyItem{
            //aqui digo lo que tiene que hacerle a KEY para hacer una de nueva
            //coger los metodos y ponerlos en un array y perderlos para así encryptar de alguna manera los metodos
            public CrazyItem()
            {
                //Random
            }
            //public CrazyItem(args) para restaurarlo
            public void Encrypt(Key keyToEncrypt)
            {

            }
            public void Decrypt(Key ketToDecrypt)
            {

            }
        }


        public List<CrazyItem> CrazyItems { get; private set; }

        public CrazyKey(int random):this()
        {
           
            RandomItems(random);
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

        public Key Encrypt(Key keyToEncrypt)
        {
            Key keyEncrypted = keyToEncrypt.Clon();

            for (int i = 0; i < CrazyItems.Count; i++)
                CrazyItems[i].Encrypt(keyEncrypted);
            return keyEncrypted;
        }
        public Key Decrypt(Key keyToDecrypt)
        {
            Key keyDecrypted = keyToDecrypt.Clon();

            for (int i = CrazyItems.Count-1; i >=0 ; i--)
                CrazyItems[i].Decrypt(keyDecrypted);
            return keyDecrypted;
        }
    }
}
