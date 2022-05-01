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
            keys = keysGenerator.Generate();
        }
        public BigInteger Encrypt(BigInteger message)//(y^m mod n) * (u^r mod n) mod n
        {
            while (true)
            {
                u = Functions.RandomInteger(2, keys.n - 1);
                if (BigInteger.GreatestCommonDivisor(u, keys.n) == 1)
                    break;
            }
            //u = Functions.RandomInteger(2, keys.n - 1);

            var left = BigInteger.ModPow(keys.y, message, keys.n);
            var right = BigInteger.ModPow(u, keys.r, keys.n);
           return BigInteger.Multiply(left, right) % keys.n;
        }
        public BigInteger Decrypt(BigInteger message)
        {
            BigInteger res;
            BigInteger count = 0;
            a = BigInteger.ModPow(message, keys.f / keys.r, keys.n);
            for (BigInteger i = 0;  i < keys.r; i++)
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

            public Keys Generate()//особо лучше не стало
            {
                Keys keys = new Keys();
                Random rnd = new Random();
                BigInteger p, q, r = 0;
                p = GetPrimeNumber();
                for(int i = 15; i > 1; i--)
                {
                    if (((p - 1) % i) == 0 && BigInteger.GreatestCommonDivisor((p - 1) / i, i) == 1)
                    {
                        r = (p - 1) / i;
                        break;
                    }
                }
               
                while (true)
                {
                    q = GetPrimeNumber();
                    if (BigInteger.GreatestCommonDivisor(r, q - 1) == 1) break;
                }
                BigInteger n = p * q;
                BigInteger phi = (p - 1) * (q - 1);
                BigInteger y, x;
                while (true)
                {
                    y = Functions.RandomInteger(1, n);
                    x = BigInteger.ModPow(y, phi / r, n);
                    if (x != 1) break;
                }
                keys.x = x;
                keys.y = y;
                keys.n = n;
                keys.f = phi;
                keys.r = r;
                return keys;
              
            }

            public Keys GenerateKeys(BigInteger message)
            {
                Keys keys;
                var random = new Random();
                BigInteger q;
                BigInteger p = GetPrimeNumber();
                BigInteger r = message;//что это блять за число такое
                
                while (true)
                {
                    r++;     
                    if ((p - 1) % r == 0 && BigInteger.GreatestCommonDivisor(r, (p - 1) / r) == 1 && r > message)
                        break;
                }
                while (true)
                {
                    q = GetPrimeNumber();
                    if (BigInteger.GreatestCommonDivisor(r, q - 1) == 1)
                        break;
                }
                /*MillerRabinTest test = new MillerRabinTest();
                if (test.MakeSimplicityTest(r, probability)) 
                    Console.WriteLine("hmmmm");*/

                keys.r = r;
                keys.n = BigInteger.Multiply(p, q);
                keys.f = BigInteger.Multiply(p - 1, q - 1);
                var pow = keys.f / keys.r;
                BigInteger y = Functions.RandomInteger(2, keys.n - 1);
                while (BigInteger.ModPow(y, pow, keys.n) == 1 && BigInteger.GreatestCommonDivisor(y, keys.n) == 1)
                {
                    y = Functions.RandomInteger(2, keys.n - 1);
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

            public BigInteger GetPrimeNumber(ulong size)
            {
                BigInteger newBigInt;
                var random = new Random();
                byte[] buffer = new byte[size];
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
