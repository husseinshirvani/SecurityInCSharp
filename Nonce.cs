using System;
using System.Security.Cryptography;

namespace SecurityInCSharp
{
    class Nonce
    {
        private byte[] nonce { get; set; }

        /// <summary>
        /// Generate unique nonce value
        /// </summary>
        /// <returns></returns>
        public byte[] GenerateNonce()
        {
            byte[] nonce = new byte[4];
            var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(nonce);

            return nonce;
        }

        /// <summary>
        /// Verify input nonce is equal to generated nonce
        /// </summary>
        /// <param name="inputNonce"></param>
        /// <returns></returns>
        public bool VerifyNonce(byte[] inputNonce)
        {
            for (int i = 0; i < inputNonce.Length; i++)
            {
                if (inputNonce[i] != nonce[i])
                    return false;
            }
            return true;
        }
    }
}
