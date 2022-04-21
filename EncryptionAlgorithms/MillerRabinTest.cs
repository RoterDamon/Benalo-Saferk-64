using System;
using System.Numerics;

namespace EncryptionAlgorithms
{
    class MillerRabinTest : IProbabilisticSimplicityTest
    {
        public bool MakeSimplicityTest(BigInteger value, double minProbability)
        {
            BigInteger d = value - 1;
            int degree = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                degree += 1;
            }
            Random rnd = new Random();
            for (int i = 0; 1.0 - Math.Pow(4, -i) <= minProbability; i++)
            {
                BigInteger a = Functions.RandomInteger(2, value - 1);
                BigInteger x = BigInteger.ModPow(a, d, value);
                if (x == 1 || x == value - 1)
                    continue;
                
                for (int r = 1; r < degree; r++)
                {
                    x = BigInteger.ModPow(x, 2, value);
                    if (x == 1)
                        return false;
                    if (x == value - 1)
                        break;
                }

                if (x != value - 1)
                    return false;
            }

            return true;
        }
    }
}
