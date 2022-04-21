using System;
using System.Numerics;

namespace EncryptionAlgorithms
{
    interface IProbabilisticSimplicityTest
    {
        bool MakeSimplicityTest(BigInteger value, double minProbability);
    }
}
