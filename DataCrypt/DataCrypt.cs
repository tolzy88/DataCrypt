using DataCrypt.Core;

namespace DataCrypt
{
    /// <summary>
    /// Static Data encryption abstractions utilizing AES-256-GCM.
    /// </summary>
    public static class DataCrypt
    {
        /// <summary>
        /// The version of the DataCrypt format. If there are breaking changes this version will be incremented.
        /// </summary>
        public const uint Version = 5; // Be sure to increment FileCrypt version also

        /// <summary>
        /// Encrypt data using AES-GCM-256.
        /// </summary>
        /// <param name="password">Password used to derive key. NOTE: DataCrypt will use key stretching on this password.</param>
        /// <param name="plaintext">Data to encrypt.</param>
        /// <param name="aad">Extra data that is NOT encrypted, but is authenticated via the tag. Must be present during decryption.</param>
        /// <returns>Ciphertext byte array with embedded header.</returns>
        public static byte[] EncryptData(string password, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad = default)
        {
            using var dc = new DataCryptContext(password: password);
            return dc.Encrypt(
                plaintext: plaintext, 
                aad:  aad);
        }

        /// <summary>
        /// Encrypt data using AES-GCM-256.
        /// </summary>
        /// <param name="key">Encryption key. Must be 32 bytes exactly (256 Bits).</param>
        /// <param name="plaintext">Data to encrypt.</param>
        /// <param name="aad">Extra data that is NOT encrypted, but is authenticated via the tag. Must be present during decryption.</param>
        /// <returns>Ciphertext byte array with embedded header.</returns>
        public static byte[] EncryptData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad = default)
        {
            using var dc = new DataCryptContext(key: key);
            return dc.Encrypt(
                plaintext: plaintext,
                aad: aad);
        }


        /// <summary>
        /// Decrypt data using AES-GCM-256.
        /// </summary>
        /// <param name="password">Password used during encryption. NOTE: DataCrypt will use key stretching on this password.</param>
        /// <param name="ciphertext">Ciphertext with embedded header.</param>
        /// <param name="aad">Extra data that is NOT encrypted, but is authenticated via the tag. If there is none, this array will be empty.</param>
        /// <returns>Plaintext byte array.</returns>
        public static byte[] DecryptData(string password, ReadOnlySpan<byte> ciphertext, out byte[] aad)
        {
            using var dc = new DataCryptContext(
                ciphertext: ciphertext,
                password: password);
            return dc.Decrypt(
                ciphertext: ciphertext,
                out aad);
        }

        /// <summary>
        /// Decrypt data using AES-GCM-256.
        /// </summary>
        /// <param name="key">Key that was used during encryption. Must be 32 bytes exactly (256 Bits).</param>
        /// <param name="ciphertext">Ciphertext with embedded header.</param>
        /// <param name="aad">Extra data that is NOT encrypted, but is authenticated via the tag. If there is none, this array will be empty.</param>
        /// <returns>Plaintext byte array.</returns>
        public static byte[] DecryptData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, out byte[] aad)
        {
            using var dc = new DataCryptContext(
                ciphertext: ciphertext,
                key: key);
            return dc.Decrypt(
                ciphertext: ciphertext,
                out aad);
        }

    }
}
