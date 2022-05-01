using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAlgorithms
{
    class Modes
    {
        public enum EncryptionMode { CBC, CFB, OFB, CTR, RD, RDH };
        public EncryptionMode encryptionMode;
        public byte[] InitializationVector;
        static int BlockSize = 8;
        public IEncrDecrFunctionality algorithm;

        public Modes(EncryptionMode mode, byte[] vector)
        {
            encryptionMode = mode;
            InitializationVector = vector;
        }
        public byte[] Encrypt(byte[] data)
        {
            byte[] res = MakePaddingPKCS7(data);
            List<byte[]> blocks = new List<byte[]>();
            switch (encryptionMode)
            {
                case EncryptionMode.CBC:
                    {
                        byte[] prevBlock = new byte[BlockSize];
                        byte[] curBlock = new byte[BlockSize];
                        Array.Copy(InitializationVector, prevBlock, prevBlock.Length);
                        for (int i = 0; i < res.Length / BlockSize; i++)
                        {
                            Array.Copy(res, i * BlockSize, curBlock, 0, BlockSize);
                            blocks.Add(algorithm.EncryptBlock(XOR(curBlock, prevBlock)));
                            Array.Copy(blocks[i], prevBlock, BlockSize);
                        }
                        break;
                    }
                case EncryptionMode.CFB://curEncBlock = E(prevEncBlock) ^ block
                    {
                        byte[] prevBlock = new byte[BlockSize];
                        byte[] curBlock = new byte[BlockSize];
                        Array.Copy(InitializationVector, prevBlock, prevBlock.Length);
                        for (int i = 0; i < res.Length / BlockSize; i++)
                        {
                            Array.Copy(res, i * BlockSize, curBlock, 0, BlockSize);
                            blocks.Add(XOR(algorithm.EncryptBlock(prevBlock), curBlock));
                            Array.Copy(blocks[i], prevBlock, BlockSize);
                        }
                        break;
                    }
                case EncryptionMode.OFB:
                    {
                        byte[] prevBlock = new byte[BlockSize];
                        byte[] curBlock = new byte[BlockSize];
                        byte[] encryptBlock = new byte[BlockSize];
                        Array.Copy(InitializationVector, prevBlock, prevBlock.Length);
                        for (int i = 0; i < res.Length / BlockSize; i++)
                        {
                            Array.Copy(res, i * BlockSize, curBlock, 0, BlockSize);
                            encryptBlock = algorithm.EncryptBlock(prevBlock);
                            blocks.Add(XOR(encryptBlock, curBlock));
                            Array.Copy(encryptBlock, prevBlock, BlockSize);
                        }
                        break;
                    }
                case EncryptionMode.CTR:
                    {
                        var copyIV = new byte[8];
                        InitializationVector.CopyTo(copyIV, 0);
                        var counter = BitConverter.ToUInt64(copyIV);
                        byte[] curBlock = new byte[BlockSize];
                        for (int i = 0; i < res.Length / BlockSize; i++)
                        {
                            Array.Copy(res, i * BlockSize, curBlock, 0, BlockSize);
                            blocks.Add(XOR(algorithm.EncryptBlock(copyIV), curBlock));
                            counter++;
                            copyIV = BitConverter.GetBytes(counter);
                        }
                        break;
                    }
                case EncryptionMode.RD:
                    {
                        byte[] curBlock = new byte[BlockSize];
                        byte[] DeltaArr = new byte[8];
                        Array.Copy(InitializationVector, 8, DeltaArr, 0, BlockSize);
                        var copyIV = new byte[8];
                        Array.Copy(InitializationVector, 0, copyIV, 0, BlockSize);
                        var IV = BitConverter.ToUInt64(copyIV);
                        var Delta = BitConverter.ToUInt64(DeltaArr);
                        blocks.Add(algorithm.EncryptBlock(copyIV));
                        for (int i = 0; i < res.Length / BlockSize; i++)
                        {
                            Array.Copy(res, i * BlockSize, curBlock, 0, BlockSize);
                            blocks.Add(algorithm.EncryptBlock(XOR(copyIV, curBlock)));
                            IV += Delta;
                            copyIV = BitConverter.GetBytes(IV);
                        }
                        break;
                    }
                case EncryptionMode.RDH:
                    {
                        byte[] curBlock = new byte[BlockSize];
                        byte[] DeltaArr = new byte[8];
                        Array.Copy(InitializationVector, 8, DeltaArr, 0, BlockSize);
                        var copyIV = new byte[8];
                        Array.Copy(InitializationVector, 0, copyIV, 0, BlockSize);
                        var IV = BitConverter.ToUInt64(copyIV);
                        var Delta = BitConverter.ToUInt64(DeltaArr);
                        blocks.Add(algorithm.EncryptBlock(copyIV));
                        //blocks.Add(XOR(copyIV, MakePaddingPKCS7(BitConverter.GetBytes(param.GetHashCode()))));
                        for (int i = 0; i < res.Length / BlockSize; i++)
                        {
                            IV += Delta;
                            copyIV = BitConverter.GetBytes(IV);
                            Array.Copy(res, i * BlockSize, curBlock, 0, BlockSize);
                            blocks.Add(algorithm.EncryptBlock(XOR(copyIV, curBlock)));
                        }
                        break;
                    }
            }
            return MakeArrayFromList(blocks);
        }

        public byte[] Decrypt(byte[] data)
        {
            List<byte[]> blocks = new List<byte[]>();
            switch (encryptionMode)
            {
                case EncryptionMode.CBC:
                    {
                        byte[] prevBlock = new byte[BlockSize];
                        byte[] curBlock = new byte[BlockSize];
                        Array.Copy(InitializationVector, prevBlock, prevBlock.Length);
                        for (int i = 0; i < data.Length / BlockSize; i++)
                        {
                            Array.Copy(data, i * BlockSize, curBlock, 0, BlockSize);
                            blocks.Add(XOR(prevBlock, algorithm.DecryptBlock(curBlock)));
                            Array.Copy(curBlock, prevBlock, BlockSize);
                        }
                        break;
                    }
                case EncryptionMode.CFB:
                    {
                        byte[] prevBlock = new byte[BlockSize];
                        byte[] curBlock = new byte[BlockSize];
                        Array.Copy(InitializationVector, prevBlock, prevBlock.Length);
                        for (int i = 0; i < data.Length / BlockSize; i++)
                        {
                            Array.Copy(data, i * BlockSize, curBlock, 0, BlockSize);
                            blocks.Add(XOR(algorithm.EncryptBlock(prevBlock), curBlock));
                            Array.Copy(curBlock, prevBlock, BlockSize);
                        }
                        break;
                    }
                case EncryptionMode.OFB:
                    {
                        byte[] prevBlock = new byte[BlockSize];
                        byte[] curBlock = new byte[BlockSize];
                        byte[] encryptBlock = new byte[BlockSize];
                        Array.Copy(InitializationVector, prevBlock, prevBlock.Length);
                        for (int i = 0; i < data.Length / BlockSize; i++)
                        {
                            Array.Copy(data, i * BlockSize, curBlock, 0, BlockSize);
                            encryptBlock = algorithm.EncryptBlock(prevBlock);
                            blocks.Add(XOR(encryptBlock, curBlock));
                            Array.Copy(encryptBlock, prevBlock, BlockSize);
                        }
                        break;
                    }
                case EncryptionMode.CTR:
                    {
                        var counter = BitConverter.ToUInt64(InitializationVector);
                        byte[] curBlock = new byte[BlockSize];
                        for (int i = 0; i < data.Length / BlockSize; i++)
                        {
                            Array.Copy(data, i * BlockSize, curBlock, 0, BlockSize);
                            blocks.Add(XOR(algorithm.EncryptBlock(InitializationVector), curBlock));
                            counter++;
                            InitializationVector = BitConverter.GetBytes(counter);
                        }
                        break;
                    }
                case EncryptionMode.RD:
                    {
                        byte[] curBlock = new byte[BlockSize];
                        byte[] DeltaArr = new byte[8];
                        Array.Copy(InitializationVector, InitializationVector.Length / 2, DeltaArr, 0, BlockSize);
                        var copyIV = new byte[8];
                        var Delta = BitConverter.ToUInt64(DeltaArr);
                        Array.Copy(data, 0, curBlock, 0, BlockSize);
                        copyIV = algorithm.DecryptBlock(curBlock);
                        var IV = BitConverter.ToUInt64(copyIV);
                        for (int i = 1; i < data.Length / BlockSize; i++)
                        {
                            Array.Copy(data, i * BlockSize, curBlock, 0, BlockSize);
                            blocks.Add(XOR(algorithm.DecryptBlock(curBlock), copyIV));
                            IV += Delta;
                            copyIV = BitConverter.GetBytes(IV);
                        }
                        break;
                    }
                case EncryptionMode.RDH:
                    {
                        byte[] curBlock = new byte[BlockSize];
                        byte[] DeltaArr = new byte[8];
                        Array.Copy(InitializationVector, InitializationVector.Length / 2, DeltaArr, 0, BlockSize);
                        var copyIV = new byte[8];
                        var Delta = BitConverter.ToUInt64(DeltaArr);
                        Array.Copy(data, 0, curBlock, 0, BlockSize);
                        copyIV = algorithm.DecryptBlock(curBlock);
                        var IV = BitConverter.ToUInt64(copyIV);
                        Array.Copy(data, 8, curBlock, 0, BlockSize);
                        /*if (!(XOR(copyIV, MakePaddingPKCS7(BitConverter.GetBytes(param.GetHashCode())))).SequenceEqual(curBlock))
                            break;*/

                        for (int i = 2; i < data.Length / BlockSize; i++)
                        {
                            IV += Delta;
                            copyIV = BitConverter.GetBytes(IV);
                            Array.Copy(data, i * BlockSize, curBlock, 0, BlockSize);
                            blocks.Add(XOR(algorithm.DecryptBlock(curBlock), copyIV));
                        }
                        break;
                    }
            }
            byte[] array = MakeArrayFromList(blocks);
            byte extraBlocks = array[array.Length - 1];
            var res = new byte[array.Length - extraBlocks];
            Array.Copy(array, res, res.Length);
            return res;
        }

        private byte[] MakePaddingPKCS7(byte[] data)
        {
            byte mod = (byte)(BlockSize - data.Length % BlockSize);
            mod = (byte)(mod == 0 ? BlockSize : mod);
            byte[] addedData = new byte[data.Length + mod];
            Array.Copy(data, addedData, data.Length);
            Array.Fill(addedData, mod, data.Length, mod);
            return addedData;
        }


        private byte[] MakeArrayFromList(List<byte[]> data)
        {
            byte[] res = new byte[BlockSize * data.Count];
            for (int i = 0; i < data.Count; i++)
            {
                Array.Copy(data[i], 0, res, i * BlockSize, BlockSize);
            }
            return res;
        }

        private byte[] XOR(byte[] left, byte[] right)
        {
            byte[] res = new byte[left.Length];
            for (int i = 0; i < left.Length; i++)
            {
                res[i] = (byte)(left[i] ^ right[i]);
            }
            return res;
        }
    }
}
