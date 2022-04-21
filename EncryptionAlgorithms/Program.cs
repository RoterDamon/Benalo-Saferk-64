using System;
using System.Numerics;

namespace EncryptionAlgorithms
{
    class Program
    {
        static void Main(string[] args)
        {
            Benalo benalo = new Benalo(78, Benalo.TestMode.Fermat, 0.7, 10);
            BigInteger encryptInt = benalo.Encrypt(78);
            BigInteger decryptInt = benalo.Decrypt(encryptInt);
        }
    }
}
