using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAlgorithms
{
    class Functions
    {
        public static BigInteger Jacobi(BigInteger a, BigInteger n)
        {
            int value;

            if (a == 1) return 1;

            value = (((n - 1) / 2) % 2 == 0 ? 1 : -1);
            if (a < 0) return Jacobi(-a, n) * value;

            value = (((n * n - 1) / 8) % 2 == 0 ? 1 : -1);
            if (a % 2 == 0) return Jacobi(a / 2, n) * value;

            value = (((a - 1) * (n - 1) / 4) % 2 == 0 ? 1 : -1);
            return value * Jacobi(n % a, a);
        }
        public static BigInteger Legendre(BigInteger a, BigInteger p)
        {
            a %= p;
            if (a == 0) return 0;

            if (a == 1) return 1;

            int value = (((a - 1) * (p - 1) / 4) % 2 == 0 ? 1 : -1);
            if (a % 2 != 0) return Legendre(p % a, a) * value;

            value = (((p * p - 1) / 8) % 2 == 0 ? 2 : 1);
            return Legendre(a / 2, p) * value;
        }

        public static BigInteger RandomInteger(BigInteger belov, BigInteger above)
        {
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] bytes = above.ToByteArray();
            BigInteger R;
            do
            {
                rng.GetBytes(bytes);
                R = new BigInteger(bytes);
            } while (!(R >= belov && R <= above));

            return R;
        }

        public static BigInteger QuickPow(BigInteger b, BigInteger degree, BigInteger mod)
        {
            BigInteger result = 1;
            BigInteger bitesForMask = degree;
            while (bitesForMask > 0)
            {
                if ((bitesForMask & 0b01) == 1)
                {
                    result = (result * b) % mod;
                }
                bitesForMask >>= 1;

                b *= b % mod;
            }
            return result;
        }

        public static BigInteger EuclideanAlgorithm(BigInteger m, BigInteger n)
        {
            while (m != 0 && n != 0)
            {
                if (m > n)
                    m = m % n;
                else
                    n = n % m;
            }
            return m + n;
        }
        public static BigInteger ExtendedEuclideanAlgorithm(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y)
        {
            if (b == 0)
            {
                x = 1;
                y = 0;
                return a;
            }
            BigInteger tmpX;
            BigInteger tmpY;
            BigInteger gcd = ExtendedEuclideanAlgorithm(b, a % b, out tmpX, out tmpY);

            y = tmpX - tmpY * (a / b);
            x = tmpY;
            return gcd;
        }
    }
}
