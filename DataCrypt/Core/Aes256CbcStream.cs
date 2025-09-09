using DataCrypt.Common;
using DataCrypt.Internal;
using System.Security.Cryptography;

namespace DataCrypt.Core
{
    /// <summary>
    /// A stream that encrypts or decrypts data using AES-256 encryption in CBC mode.
    /// Automatically handles encryptor/decryptor setup and Key Derivation.
    /// </summary>
    public class Aes256CbcStream : CryptoStream
    {
        private readonly byte[] _iv;
        private readonly byte[] _salt;

        /// <summary>
        /// The initialization vector (IV) used for encryption or decryption.
        /// </summary>
        public ReadOnlyMemory<byte> IV => _iv;
        /// <summary>
        /// The salt used for key derivation (if using a password, otherwise NULL).
        /// </summary>
        public ReadOnlyMemory<byte> Salt => _salt;

        /// <summary>
        /// Creates a new instance of the DataCryptStream class.
        /// </summary>
        /// <param name="stream">The stream on which to perform the cryptographic transformation.</param>
        /// <param name="password">The password to derive the encryption key from. Must be at least 8 characters. This will utilize PBKDF2 Key Stretching and require a Salt.</param>
        /// <param name="cryptoMode">Encryption or Decryption operation.</param>
        /// <param name="streamMode">The mode of the stream.</param>
        /// <param name="iv">IV used for Encryption/Decryption. If encrypting - leave NULL to have one randomly generated (See the IV property). If decrypting - you MUST specify the IV used during encryption.</param>
        /// <param name="salt">Salt used for PBKDF2 (if using a password). If encrypting - leave NULL to have one randomly generated (See the Salt property). If decrypting - you MUST specify the Salt used during encryption.</param>
        public Aes256CbcStream(Stream stream, string password, CryptoMode cryptoMode, CryptoStreamMode streamMode, ReadOnlySpan<byte> iv = default, ReadOnlySpan<byte> salt = default)
            : this(stream, DeriveKeyFromPassword(password, cryptoMode, ref salt), cryptoMode, streamMode, leaveOpen: false, iv)
        {
            _salt = salt.ToArray(); // Create a copy to prevent possible mutation
        }

        /// <summary>
        /// Creates a new instance of the DataCryptStream class.
        /// </summary>
        /// <param name="stream">The stream on which to perform the cryptographic transformation.</param>
        /// <param name="password">The password to derive the encryption key from. Must be at least 8 characters. This will utilize PBKDF2 Key Stretching and require a Salt.</param>
        /// <param name="cryptoMode">Encryption or Decryption operation.</param>
        /// <param name="streamMode">The mode of the stream.</param>
        /// <param name="leaveOpen">true to not close the underlying stream when the CryptoStream object is disposed; otherwise, false.</param>
        /// <param name="iv">IV used for Encryption/Decryption. If encrypting - leave NULL to have one randomly generated (See the IV property). If decrypting - you MUST specify the IV used during encryption.</param>
        /// <param name="salt">Salt used for PBKDF2 (if using a password). If encrypting - leave NULL to have one randomly generated (See the Salt property). If decrypting - you MUST specify the Salt used during encryption.</param>
        public Aes256CbcStream(Stream stream, string password, CryptoMode cryptoMode, CryptoStreamMode streamMode, bool leaveOpen, ReadOnlySpan<byte> iv = default, ReadOnlySpan<byte> salt = default)
            : this(stream, DeriveKeyFromPassword(password, cryptoMode, ref salt), cryptoMode, streamMode, leaveOpen, iv)
        {
            _salt = salt.ToArray(); // Create a copy to prevent possible mutation
        }

        /// <summary>
        /// Creates a new instance of the DataCryptStream class.
        /// </summary>
        /// <param name="stream">The stream on which to perform the cryptographic transformation.</param>
        /// <param name="key">Encryption/Decryption Key. Must be 32 bytes exactly.</param>
        /// <param name="cryptoMode">Encryption or Decryption operation.</param>
        /// <param name="streamMode">The mode of the stream.</param>
        /// <param name="iv">IV used for Encryption/Decryption. If encrypting - leave NULL to have one randomly generated (See the IV property). If decrypting - you MUST specify the IV used during encryption.</param>
        public Aes256CbcStream(Stream stream, ReadOnlySpan<byte> key, CryptoMode cryptoMode, CryptoStreamMode streamMode, ReadOnlySpan<byte> iv = default)
            : base(stream, CreateCryptoTransform(key, cryptoMode, ref iv), streamMode, leaveOpen: false)
        {
            _iv = iv.ToArray(); // Create a copy to prevent possible mutation
        }

        /// <summary>
        /// Creates a new instance of the DataCryptStream class.
        /// </summary>
        /// <param name="stream">The stream on which to perform the cryptographic transformation.</param>
        /// <param name="key">Encryption/Decryption Key. Must be 32 bytes exactly.</param>
        /// <param name="cryptoMode">Encryption or Decryption operation.</param>
        /// <param name="streamMode">The mode of the stream.</param>
        /// <param name="leaveOpen">true to not close the underlying stream when the CryptoStream object is disposed; otherwise, false.</param>
        /// <param name="iv">IV used for Encryption/Decryption. If encrypting - leave NULL to have one randomly generated (See the IV property). If decrypting - you MUST specify the IV used during encryption.</param>
        public Aes256CbcStream(Stream stream, ReadOnlySpan<byte> key, CryptoMode cryptoMode, CryptoStreamMode streamMode, bool leaveOpen, ReadOnlySpan<byte> iv = default)
            : base(stream, CreateCryptoTransform(key, cryptoMode, ref iv), streamMode, leaveOpen)
        {
            _iv = iv.ToArray(); // Create a copy to prevent possible mutation
        }

        private static ICryptoTransform CreateCryptoTransform(ReadOnlySpan<byte> key, CryptoMode mode, ref ReadOnlySpan<byte> iv)
        {
            DataCryptInternal.ThrowIfInvalidKey(key);
            if (mode == CryptoMode.Decrypt && iv.IsEmpty)
                throw new ArgumentNullException(nameof(iv), "IV must be provided for decryption.");
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = 256;
            aes.Key = key.ToArray();
            if (iv.IsEmpty)
                iv = aes.IV.ToArray();
            else
                aes.IV = iv.ToArray();
            if (iv.Length != 16)
                throw new ArgumentOutOfRangeException(nameof(iv), "IV must be 16 bytes long.");
            if (mode == CryptoMode.Encrypt)
            {
                return aes.CreateEncryptor();
            }
            else
            {
                return aes.CreateDecryptor();
            }
        }

        private static byte[] DeriveKeyFromPassword(string password, CryptoMode mode, ref ReadOnlySpan<byte> salt)
        {
            if (salt.IsEmpty)
            {
                if (mode == CryptoMode.Decrypt)
                    throw new ArgumentNullException(nameof(salt), "Salt must be provided for decryption.");
                salt = RandomNumberGenerator.GetBytes(count: 16);
            }
            return DataCryptInternal.DeriveKeyFromPassword(
                password: password,
                salt: salt);
        }
    }
}
