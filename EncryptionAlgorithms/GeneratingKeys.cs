﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAlgorithms
{
    interface GeneratingKeys
    {
        byte[][] GenerateRoundKeys(byte[] key);

    }
}