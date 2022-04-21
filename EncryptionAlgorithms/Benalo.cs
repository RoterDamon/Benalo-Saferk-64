using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAlgorithms
{
    struct Keys
    {
        public BigInteger n;    //p*q
        public BigInteger y, r;    //public key
        public BigInteger f, x;   //private key
        
    }
    class Benalo
    {
        public enum TestMode { Fermat, MillerRabin, SolovayStrassen };
        Keys keys;
        BigInteger u, a;
        public Benalo(BigInteger message, TestMode mode, double minProbability, ulong size)
        {
            KeysGenerator keysGenerator = new KeysGenerator(mode, minProbability, size);
            keys = keysGenerator.GenerateKeys(message);
        }
        public BigInteger Encrypt(BigInteger message)//(y^m mod n) * (u^r mod n) mod n
        {
            u = Functions.RandomInteger(0, keys.n);
            var left = BigInteger.ModPow(keys.y, message, keys.n);
            var right = BigInteger.ModPow(u, keys.r, keys.n);
           return BigInteger.Multiply(left, right) % keys.n;
        }
        public BigInteger Decrypt(BigInteger message)
        {
            BigInteger res = 0;
            BigInteger count = 0;
            a = BigInteger.ModPow(message, keys.f / keys.r, keys.n);
            for (BigInteger i = 0;  i <= keys.r; i++)
            {
                res = BigInteger.ModPow(keys.x, i, keys.n);
                if (res == a)
                    count = i;
            }
            return count;
        }
        class KeysGenerator
        {
            public TestMode testMode;
            double probability;
            UInt64 numSize;
            public KeysGenerator(TestMode mode, double minProbability, ulong size)
            {
                testMode = mode;
                probability = minProbability;
                numSize = size;
            }

            public Keys GenerateKeys(BigInteger message)
            {
                Keys keys;
                var random = new Random();
                BigInteger p;
                BigInteger q;
                BigInteger r = Functions.RandomInteger(message, 100);//что это блять за число такое
                BigInteger y = random.Next();
                while (true)
                {
                    p = GetPrimeNumber();
                    q = GetPrimeNumber();
                    if ((p - 1) % r == 0 && Functions.EuclideanAlgorithm(r, (p - 1) / r) == 1
                                        && Functions.EuclideanAlgorithm(r, q - 1) == 1)
                        break;
                }
                keys.r = r;
                keys.n = BigInteger.Multiply(p, q);
                keys.f = BigInteger.Multiply(p - 1, q - 1);
                var pow = keys.f / keys.r;
                
                while (BigInteger.ModPow(y, pow, keys.n) == 1)
                {
                    y = random.Next();
                }
                keys.y = y;
                keys.x = BigInteger.ModPow(keys.y, pow, keys.n);
                return keys;
            }

            public BigInteger GetPrimeNumber()
            {
                BigInteger newBigInt;
                var random = new Random();
                byte[] buffer = new byte[numSize];
                while (true)
                {
                    do
                    {
                        random.NextBytes(buffer);
                        newBigInt = new BigInteger(buffer);

                    } while (newBigInt < 2);

                    switch (testMode)
                    {
                        case TestMode.Fermat:
                            {
                                FermatTest test = new FermatTest();
                                if (test.MakeSimplicityTest(newBigInt, probability)) return newBigInt;
                                break;
                            }
                        case TestMode.MillerRabin:
                            {
                                MillerRabinTest test = new MillerRabinTest();
                                if (test.MakeSimplicityTest(newBigInt, probability)) return newBigInt;
                                break;
                            }
                        case TestMode.SolovayStrassen:
                            {
                                SolovayStrassenTest test = new SolovayStrassenTest();
                                if (test.MakeSimplicityTest(newBigInt, probability)) return newBigInt;
                                break;
                            }
                    }
                }
            }

        }

    }
}
