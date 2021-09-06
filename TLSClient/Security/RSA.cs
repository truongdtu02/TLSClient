using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Security
{
    class RSA
    {
        internal RSAParameters publicKey { get; private set; }
        private RSAParameters privateKey;
        //static string CONTAINER_NAME = "MyContainerName";
        enum eKeySizes
        {
            SIZE_512 = 512,
            SIZE_1024 = 1024,
            SIZE_2048 = 2048
        }
        //example
        public void Run()
        {
            string message = "The quick brown for jumps";

            GenerateKey();

            File.WriteAllBytes(@"D:\pubkey.txt", publicKey.Modulus);

            //byte[] encrypted = new byte[300];//Encrypt(Encoding.UTF8.GetBytes(message));
            //Random rd = new Random();
            //rd.NextBytes(encrypted);
            //Encrypt(encrypted);

            byte[] encrypted = File.ReadAllBytes(@"D:\cippher.txt");

            byte[] decrypted = Decrypt(encrypted);

            string plainText = Encoding.UTF8.GetString(decrypted);

            Console.WriteLine("done");
        }

        public RSA()
        {
            //GenerateKey();
        }

        void GenerateKey()
        {
            using(var rsa = new RSACryptoServiceProvider((int)eKeySizes.SIZE_2048))
            {
                rsa.PersistKeyInCsp = false;
                publicKey = rsa.ExportParameters(false);
                privateKey = rsa.ExportParameters(true);
                //for(int i = 0; i < publicKey.Modulus.Length; i++)
                //{
                //    Console.Write(publicKey.Modulus[i]);
                //    if (i < (publicKey.Modulus.Length - 1)) Console.Write(", ");
                //}
                //Console.WriteLine("");
            }
        }

        internal byte[] Encrypt(byte[] input)
        {
            byte[] encrypted;
            using (var rsa = new RSACryptoServiceProvider((int)eKeySizes.SIZE_2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(publicKey);
                try
                {
                    encrypted = rsa.Encrypt(input, false);
                }
                catch
                {
                    return null;
                }
            }
            //trick exchange first and last two bytes
            byte tmp = encrypted[0]; encrypted[0] = encrypted[1]; encrypted[1] = tmp;
            int lastIndx = encrypted.Length - 1;
            tmp = encrypted[lastIndx - 1]; encrypted[lastIndx - 1] = encrypted[lastIndx]; encrypted[lastIndx] = tmp;
            return encrypted;
        }

        internal static byte[] Encrypt(byte[] input, byte[] _pubKey, byte[] _exponent)
        {
            //trick exchange first and last two bytes of pubkey
            byte tmp = _pubKey[0]; _pubKey[0] = _pubKey[1]; _pubKey[1] = tmp;
            int lastIndx = _pubKey.Length - 1;
            tmp = _pubKey[lastIndx - 1]; _pubKey[lastIndx - 1] = _pubKey[lastIndx]; _pubKey[lastIndx] = tmp;

            byte[] encrypted;
            RSAParameters pubKey = new RSAParameters();
            using (var rsa = new RSACryptoServiceProvider((int)eKeySizes.SIZE_2048))
            {
                pubKey.Modulus = _pubKey;
                pubKey.Exponent = _exponent;
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(pubKey);
                try
                {
                    encrypted = rsa.Encrypt(input, false);
                }
                catch
                {
                    return null;
                }
            }

            //trick exchange first and last two bytes
            tmp = encrypted[0]; encrypted[0] = encrypted[1]; encrypted[1] = tmp;
            lastIndx = encrypted.Length - 1;
            tmp = encrypted[lastIndx - 1]; encrypted[lastIndx - 1] = encrypted[lastIndx]; encrypted[lastIndx] = tmp;
            return encrypted;
        }

        internal byte[] Decrypt(byte[] input)
        {
            //trick exchange first and last two bytes
            byte tmp = input[0]; input[0] = input[1]; input[1] = tmp;
            int lastIndx = input.Length - 1;
            tmp = input[lastIndx - 1]; input[lastIndx - 1] = input[lastIndx]; input[lastIndx] = tmp;

            byte[] decrypted;
            using (var rsa = new RSACryptoServiceProvider((int)eKeySizes.SIZE_2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(privateKey);
                try
                {
                    decrypted = rsa.Decrypt(input, false);
                }
                catch
                {
                    return null;
                }
            }
            return decrypted;
        }
    }
}
