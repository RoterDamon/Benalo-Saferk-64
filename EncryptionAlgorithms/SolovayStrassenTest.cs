using System;
using System.Numerics;

namespace EncryptionAlgorithms
{
    class SolovayStrassenTest : IProbabilisticSimplicityTest
    {
        public bool MakeSimplicityTest(BigInteger value, double minProbability)
        {
            Random rnd = new Random();
            for (int i = 0; 1.0-Math.Pow(2, -i) <= minProbability; i++)
            {
                BigInteger a = Functions.RandomInteger(2, value - 1);
                if (BigInteger.GreatestCommonDivisor(a, value) > 1)
                {
                    return false;
                }
                if (Functions.QuickPow(a, (value - 1) / 2, value) != Functions.Jacobi(a, value))
                {
                    return false; // составное
                }
            }

            return true;
        }

    }
}
