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

            keyOrigen = Key.GetKey(10);
            key1 = cKey.Encrypt(keyOrigen);
            key2 = cKey.Encrypt(keyOrigen);

            Assert.IsTrue(key1.ItemsKey.Count == key2.ItemsKey.Count && key1.Equals(key2));
            

        }
    }
}
