using Gabriel.Cat.S.Seguretat;
using Gabriel.Cat.S.Utilitats;
using System;

namespace TestGabrielCatSSeguretat
{
    internal class Test
    {
        public delegate byte[] MethodBytes(byte[] bytes, byte[] password, LevelEncrypt level, Ordre ordre);

        public delegate string MethodString(string text, byte[] password, LevelEncrypt level, Ordre ordre);
        delegate T[] Method<T>(object obj, byte[] password, LevelEncrypt level, Ordre ordre);
        delegate T Conversion<T>(int i);
        static Random r = new Random();
        public static byte[] DamePassword()
        {
            const int LENGTH = 15 * 2;
            byte[] password = new byte[LENGTH];
            r.NextBytes(password);
            return password;
        }
        public static bool TestMethodBytes(MethodBytes methodEncrypt,MethodBytes methodDecrypt)
        {
            return TestMethod<byte>((objs, password, level, ordre) => methodEncrypt((byte[])objs, password, level, ordre), (objs, password, level, ordre) => methodDecrypt((byte[])objs, password, level, ordre), byte.MaxValue + 1, (i) => (byte)i);
        }
        public static bool TestMethodString(MethodString methodEncrypt, MethodString methodDecrypt,int length= char.MaxValue + 1,int posInicialArray=0,LevelEncrypt maxLevel=LevelEncrypt.Highest)
        {
            return TestMethod<char>((objs, password, level, ordre) => methodEncrypt(new string((char[])objs), password, level, ordre).ToCharArray(), (objs, password, level, ordre) => methodDecrypt(new string((char[])objs), password, level, ordre).ToCharArray(), length, (i) => (char)i,posInicialArray,maxLevel);
        }
        static bool TestMethod<T>(Method<T> methodEncrypt, Method<T> methodDecrypt,int length,Conversion<T> conversion, int posInicialArray = 0, LevelEncrypt maxLevel = LevelEncrypt.Highest)
        {
            T[] original = new T[length];
            byte[] password = DamePassword();
            T[] cifrado;
            T[] descifrado;
            LevelEncrypt level = LevelEncrypt.Lowest;
            bool correcto = true;
            for (int i = 0, j = posInicialArray; i < original.Length; i++,j++)
                original[i] = conversion(j);
            do
            {
                cifrado = methodEncrypt(original, password, level, Ordre.Consecutiu);
                descifrado = methodDecrypt(cifrado, password, level++, Ordre.Consecutiu);
                for (int i = 0; i < descifrado.Length && correcto; i++)
                    correcto = original[i].Equals(descifrado[i]);
            } while (correcto && level <= maxLevel);
            if (correcto)
            {
                level = LevelEncrypt.Lowest;
                do
                {
                    cifrado = methodEncrypt(original, password, level, Ordre.ConsecutiuIAlInreves);
                    descifrado = methodDecrypt(cifrado, password, level++, Ordre.ConsecutiuIAlInreves);
                    for (int i = 0; i < descifrado.Length && correcto; i++)
                        correcto = original[i].Equals(descifrado[i]);
                } while (correcto && level <= maxLevel);
            }
            return correcto;
        }
    }
}
