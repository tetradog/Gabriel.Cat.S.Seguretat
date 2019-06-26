using System;
using Gabriel.Cat.S.Seguretat;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TestGabrielCatSSeguretat
{
    [TestClass]
    public class CrazyKeyTest
    {
        [TestMethod]
        public void GenerarDosVecesLaMismaClaveCorrectamente()
        {
            Key key1, key2, keyOrigen;
            CrazyKey cKey=new CrazyKey(5);

            keyOrigen = Key.GetKey(100);
            key1 = cKey.Encrypt(keyOrigen);
            key2 = cKey.Encrypt(keyOrigen);
            
            Assert.IsTrue(key1.ItemsKey.Count == key2.ItemsKey.Count && key1.Equals(key2));
            

        }
        [TestMethod]
        public void GenerarDosVecesLaMismaClaveCorrectamente2CrazyKey()
        {
            Key key1, key2, keyOrigen;

            CrazyKey cKey = new CrazyKey(5);
            CrazyKey cKey2 = new CrazyKey(5);

            keyOrigen = Key.GetKey(100);
            key1 = cKey2.Encrypt(cKey.Encrypt(keyOrigen));
            key2 = cKey2.Encrypt(cKey.Encrypt(keyOrigen));

            Assert.IsTrue(key1.ItemsKey.Count == key2.ItemsKey.Count && key1.Equals(key2));


        }
        [TestMethod]
        public void GenerarDosVecesLaMismaClaveCorrectamenteDobleCrazyKey()
        {
            Key key1, key2, keyOrigen;

            CrazyKey cKey = new CrazyKey(10);


            keyOrigen = Key.GetKey(100);
            key1 = cKey.Encrypt(cKey.Encrypt(keyOrigen));
            key2 = cKey.Encrypt(cKey.Encrypt(keyOrigen));

            Assert.IsTrue(key1.ItemsKey.Count == key2.ItemsKey.Count && key1.Equals(key2));


        }
        [TestMethod]
        public void GenerarKeyConCrazyKey()
        {
            new CrazyKey(10).Encrypt(Key.GetKey(100));
            Assert.IsTrue(true);
        }
        [TestMethod]
        public void GenerarBigKeyConLittleCrazyKey()
        {
            new CrazyKey(3).Encrypt(Key.GetKey(1000));
            Assert.IsTrue(true);
        }
    }
}
