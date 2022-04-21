using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAlgorithms
{
    interface EncryptionConversion
    {
        byte[] EncryptFunc(byte[] block, byte[] roundKey);

    }
}
