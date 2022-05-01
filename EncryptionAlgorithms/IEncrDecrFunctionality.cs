using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAlgorithms
{
    interface IEncrDecrFunctionality
    {
        byte[] EncryptBlock(byte[] message);

        byte[] DecryptBlock(byte[] message);

        void SetKey(byte[] key);
    }
}
