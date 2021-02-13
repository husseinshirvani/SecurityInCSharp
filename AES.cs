using System;
using System.IO;
using System.Windows.Forms;
using System.Security.Cryptography;

namespace SecurityInCSharp
{
    public class AES_Enc
    {
        public byte[] AES_Key { get; set; }
        public byte[] AES_IV { get; set; }
        private Aes myAes { get; set; }

        public AES_Enc()
        {
            myAes = Aes.Create();
            myAes.Mode = CipherMode.CBC;
            myAes.Padding = PaddingMode.PKCS7;
            AES_Key = myAes.Key;
            myAes.IV = System.Text.Encoding.ASCII.GetBytes("HR$2pIjHR$2pIj12");
            AES_IV = myAes.IV;
        }

        /// <summary>
        /// Encrypt string value using AES algorithm
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public byte[] EncryptUsingAES(string plainText)
        {
            try
            {
                byte[] encrypted = null;

                encrypted = EncryptStringToBytes_Aes(plainText, AES_Key, AES_IV);

                return encrypted;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return null;
            }
        }

        /// <summary>
        /// Decrypt encrypted string value using AES algorithm
        /// </summary>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string DecryptUsingAES(byte[] cipherText)
        {
            try
            {
                return DecryptStringFromBytes_Aes(cipherText, AES_Key, AES_IV);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return null;
            }
        }

        /// <summary>
        /// Encrypt byte array using AES algorithm
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        private byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }

                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }

        /// <summary>
        /// Decrypt ecrypted byte array using AES algorithm
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="Key"></param>
        /// <param name="IV"></param>
        /// <returns></returns>
        private string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}
