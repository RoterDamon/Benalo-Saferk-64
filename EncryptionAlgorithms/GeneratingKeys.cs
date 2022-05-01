using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAlgorithms
{
    class GeneratingKeys : IGeneratingKeys
    {
        public byte[][] GenerateRoundKeys(byte[] key)
        {
            char[] B = new char[12] { '1', '3', '0', '2', '9', '0', '4', 'F', '2', 'E', '7', '2' };
            byte[][] keys = new byte[12][];
            keys[0] = key;
            byte[] prev = new byte[8];
            for (int i = 0; i < key.Length; i++)
                prev[i] = key[i];
            for (int i = 1; i < 12; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {
                    uint shift = LeftShift(prev[j], 3);
                    uint b = Convert.ToUInt32(Convert.ToByte(B[i]));
                    keys[i][j] = Convert.ToByte((shift + b) % 256);
                }
            }
            return keys;
        }
        private uint LeftShift(uint value, int count)
        {
            return (value >> count) + (((value << (32 - count)) >> (32 - count)) << count);
        }
    }
}
