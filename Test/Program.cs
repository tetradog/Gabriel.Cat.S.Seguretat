using Gabriel.Cat.S.Seguretat;
using System;
using System.IO;
using Gabriel.Cat.S.Extension;
namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {
            Key key = Key.GetKey(100);
            FileInfo fileOri, fileEncypt,fileDecypted;
            DateTime timeInicio;
            for(; ; )
            try
            {
                Console.Clear();
                MostrarArchivos();
                fileOri = PideFichero();
                timeInicio = DateTime.Now;
                fileEncypt = key.Encrypt(fileOri);
                Console.WriteLine("Encrypted {0}ms",(DateTime.Now-timeInicio).TotalMilliseconds);
                timeInicio = DateTime.Now;
                fileDecypted = key.Decrypt(fileEncypt);
                Console.WriteLine("Decrypted {0}ms", (DateTime.Now - timeInicio).TotalMilliseconds);

                timeInicio = DateTime.Now;
                if (SonIguales(fileOri, fileDecypted))
                    Console.WriteLine("Todo bien");
                else Console.WriteLine("Hay problemas...");

                Console.WriteLine("Comparación {0}ms", (DateTime.Now - timeInicio).TotalMilliseconds);
            }
            catch(Exception ex)
            {
                Console.WriteLine("Problemas: {0}",ex.Message);
            }
            finally
            {
                Console.ReadKey();
            }
        }

        private static bool SonIguales(FileInfo fileOri, FileInfo fileDecypted)
        {
            return fileOri.GetStream().GetAllBytes().ArrayEqual(fileDecypted.GetStream().GetAllBytes());
        }

        private static FileInfo PideFichero()
        {
            int pos=-1;
            Console.Write("Elige un archivo: ");
            while (!int.TryParse(Console.ReadLine(), out pos));
            return new FileInfo(Directory.GetFiles(Environment.CurrentDirectory)[pos-1]);//resto uno porque empiezo la lista en 1 :)
        }

        private static void MostrarArchivos()
        {
            int pos = 1;
            Console.Clear();
            foreach (var file in Directory.GetFiles(Environment.CurrentDirectory))
                Console.WriteLine("{0} {1}", pos++, file);
        }
    }
}
