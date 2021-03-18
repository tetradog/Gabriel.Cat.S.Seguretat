using Gabriel.Cat.S.Extension;
using Gabriel.Cat.S.Utilitats;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Gabriel.Cat.S.Seguretat.Test
{

    [TestClass]
    public class DisimulatRandom : Test
    {
        public DisimulatRandom() : base(EncryptMethod.DisimulatRandom) { }
    }

}
