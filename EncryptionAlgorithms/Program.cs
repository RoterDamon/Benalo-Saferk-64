using System;
using System.Numerics;

namespace EncryptionAlgorithms
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("sdfghjkl");

            BigInteger message = 15842, encrypted;
            Random rnd = new Random();
            Console.WriteLine(message.GetByteCount());
            Benalo benalo;
            for (int i = 0; i < 10; i++)
            {
                message = rnd.Next(1000);
                Console.WriteLine(i + " " + message);
                benalo = new Benalo(message, Benalo.TestMode.MillerRabin, 0.7, (ulong)message.GetByteCount() + 1);
                encrypted = benalo.Decrypt(benalo.Encrypt(message));
                if (message != encrypted) Console.WriteLine("Opshipka " + message + " " + encrypted);
            }
            benalo = new Benalo(message, Benalo.TestMode.MillerRabin, 0.7, (ulong)message.GetByteCount() + 1);
            BigInteger encryptInt = benalo.Encrypt(15842);
            BigInteger decryptInt = benalo.Decrypt(encryptInt);
        }
    }
}
