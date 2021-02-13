using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace SecurityInCSharp
{
    class HMAC
    {
        private byte[] secretKey { get; set; }

        public HMAC()
        {
            secretKey = Encoding.ASCII.GetBytes("!@#$%^&*()ABCDEFG1234567");
        }

        /// <summary>
        /// Get HMAC value from input string
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public void GenerateHMACSecretKey()
        {
            byte[] secretkey = new Byte[256];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(secretkey);
                secretKey = secretkey;

                FileStream newFileOutStream = new FileStream(@"D:\HMACSecretKey.txt", FileMode.Truncate, FileAccess.Write);
                StreamWriter newStreamWriter = new StreamWriter(newFileOutStream);

                newStreamWriter.WriteLine(Convert.ToBase64String(secretKey));

                newStreamWriter.Close();
                newFileOutStream.Close();
            }
        }

        /// <summary>
        /// Get HMAC value from input string
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public byte[] GetHMACByte(string input)
        {
            byte[] combinedArray = null;

            using (HMACSHA256 hmac = new HMACSHA256(secretKey))
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hashValue = hmac.ComputeHash(inputBytes);

                combinedArray = CombineByteArrays(hashValue, inputBytes);
            }

            return combinedArray;
        }

        /// <summary>
        /// Get HMAC value from byte array
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public byte[] GetHMACByte(byte[] input)
        {
            byte[] combinedArray = null;

            using (HMACSHA256 hmac = new HMACSHA256(secretKey))
            {
                byte[] hashValue = hmac.ComputeHash(input);

                combinedArray = CombineByteArrays(hashValue, input);
            }

            return combinedArray;
        }

        /// <summary>
        /// Check HMAC value validity
        /// </summary>
        /// <param name="hashValue"></param>
        /// <returns></returns>
        public bool CheckHMAC(byte[] hashValue)
        {
            using (HMACSHA256 hmac = new HMACSHA256(secretKey))
            {
                byte[] storedHash = ReadStoredHashFromByteArray(hashValue, hmac.HashSize / 8);
                byte[] storedString = ReadStoredStringFromByteArray(hashValue, hashValue.Length - (hmac.HashSize / 8));

                byte[] computedHashValue = hmac.ComputeHash(storedString);

                for (int i = 0; i < storedHash.Length; i++)
                {
                    if (computedHashValue[i] != storedHash[i])
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        /// <summary>
        /// Combines two byte arrays
        /// </summary>
        /// <param name="firstArray"></param>
        /// <param name="secondArray"></param>
        /// <returns></returns>
        public byte[] CombineByteArrays(byte[] firstArray, byte[] secondArray)
        {
            byte[] combinedArray = new byte[firstArray.Length + secondArray.Length];

            for (int i = 0; i < firstArray.Length; i++)
                combinedArray[i] = firstArray[i];

            for (int i = firstArray.Length, k = 0; k < secondArray.Length; k++, i++)
                combinedArray[i] = secondArray[k];

            return combinedArray;
        }

        /// <summary>
        /// Read hash value from byte array
        /// </summary>
        /// <param name="inputByteArray"></param>
        /// <param name="hashLength"></param>
        /// <returns></returns>
        private byte[] ReadStoredHashFromByteArray(byte[] inputByteArray, int hashLength)
        {
            byte[] storedHash = new byte[hashLength];
            for (int i = 0; i < hashLength; i++)
                storedHash[i] = inputByteArray[i];
            return storedHash;
        }

        /// <summary>
        /// Read string value from byte array
        /// </summary>
        /// <param name="inputByteArray"></param>
        /// <param name="stringLength"></param>
        /// <returns></returns>
        private byte[] ReadStoredStringFromByteArray(byte[] inputByteArray, int stringLength)
        {
            byte[] storedString = new byte[stringLength];
            for (int i = 0; i < stringLength; i++)
                storedString[i] = inputByteArray[inputByteArray.Length - stringLength + i];
            return storedString;
        }
    }
}
