using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Security
{
    class MD5
    {
        public static byte[] MD5Hash(string input)
        {
            byte[] tmp = new UTF8Encoding().GetBytes(input);
            return MD5Hash(tmp, 0, tmp.Length);
        }

        public static byte[] MD5Hash(byte[] input, int offset, int count)
        {
            StringBuilder hash = new StringBuilder();
            MD5CryptoServiceProvider md5provider = new MD5CryptoServiceProvider();
            byte[] bytes = md5provider.ComputeHash(input, offset, count);

            return bytes;
        }

        //public static string MD5Hash(byte[] input)
        //{
        //    StringBuilder hash = new StringBuilder();
        //    MD5CryptoServiceProvider md5provider = new MD5CryptoServiceProvider();
        //    byte[] bytes = md5provider.ComputeHash(input);

        //    for (int i = 0; i < bytes.Length; i++)
        //    {
        //        hash.Append(bytes[i].ToString("x2"));
        //    }
        //    string output = hash.ToString();
        //    return hash.ToString();
        //}
    }
}
