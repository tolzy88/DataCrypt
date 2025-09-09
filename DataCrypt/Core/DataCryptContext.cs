using DataCrypt.Internal;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DataCrypt.Core
{
    /// <summary>
    /// Data encryption abstractions utilizing AES-256-GCM.
    /// Automatically handles encryptor/decryptor setup and Key Derivation.
    /// </summary>
    public sealed class DataCryptContext : IDisposable
    {
        private readonly AesGcm _aes;
        private readonly byte[] _salt;

        /// <summary>
        /// The salt used for key derivation (if using a password, otherwise NULL).
        /// </summary>
        public ReadOnlyMemory<byte> Salt => _salt;

        /// <summary>
        /// Creates a brand new instance of the DataCryptContext class that provides AES-256-GCM Encryption/Decryption.
        /// Must provide a password OR key.
        /// </summary>
        /// <param name="key">Encryption key. Must be 32 bytes exactly (256 Bits).</param>
        /// <param name="password">Password used to derive key. NOTE: DataCrypt will use key stretching on this password.</param>
        public DataCryptContext(ReadOnlySpan<byte> key = default, string password = null)
        {
            if (key.IsEmpty && string.IsNullOrEmpty(password))
                throw new ArgumentException("You must provide either a password or a key.");
            if (!key.IsEmpty && !string.IsNullOrEmpty(password))
                throw new ArgumentException("You cannot provide both a password and a key.");
            if (!string.IsNullOrEmpty(password))
            {
                ReadOnlySpan<byte> salt = default;
                key = DeriveKeyFromPassword(
                    password: password,
                    salt: ref salt);
                _salt = salt.ToArray(); // Create a copy to prevent possible mutation
            }
            Init(key, AesGcm.TagByteSizes.MaxSize, ref _aes);
        }

        /// <summary>
        /// Creates an existing instance of the DataCryptContext class (from existing Password/Salt parameters) that provides AES-256-GCM Encryption/Decryption.
        /// </summary>
        /// <param name="password">Password used to derive key. NOTE: DataCrypt will use key stretching on this password.</param>
        /// <param name="salt">Crytorandom salt used to derive key from password.</param>
        public DataCryptContext(string password, ReadOnlySpan<byte> salt)
        {
            var key = DeriveKeyFromPassword(
                password: password,
                salt: ref salt);
            _salt = salt.ToArray(); // Create a copy to prevent possible mutation
            Init(key, AesGcm.TagByteSizes.MaxSize, ref _aes);
        }

        /// <summary>
        /// Creates an existing instance of the DataCryptContext class (from ciphertext) that provides AES-256-GCM Encryption/Decryption.
        /// Must provide a password OR key.
        /// </summary>
        /// <param name="ciphertext">Ciphertext with embedded header.</param>
        /// <param name="key">Encryption key. Must be 32 bytes exactly (256 Bits).</param>
        /// <param name="password">Password used to derive key. NOTE: DataCrypt will use key stretching on this password.</param>
        /// <exception cref="ArgumentException"></exception>
        public DataCryptContext(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key = default, string password = null)
        {
            if (key.IsEmpty && string.IsNullOrEmpty(password))
                throw new ArgumentException("You must provide either a password or a key.");
            if (!key.IsEmpty && !string.IsNullOrEmpty(password))
                throw new ArgumentException("You cannot provide both a password and a key.");
            var header = MemoryMarshal.Read<DataCryptHeader>(ciphertext);
            if (header.Version != DataCrypt.Version)
            {
                throw new InvalidOperationException($"DataCrypt version mismatch. Please use DataCrypt 'Version {header.Version}' for this data.");
            }
            if (!string.IsNullOrEmpty(password))
            {
                var salt = ciphertext.Slice(
                    start: DataCryptHeader.Size,
                    length: header.SaltSize);
                key = DeriveKeyFromPassword(
                    password: password,
                    salt: ref salt);
                _salt = salt.ToArray(); // Create a copy to prevent possible mutation
            }
            Init(key, header.TagSize, ref _aes);
        }

        private static void Init(ReadOnlySpan<byte> key, int tagSize, ref AesGcm aes)
        {
            DataCryptInternal.ThrowIfInvalidKey(key);
#if NET8_0_OR_GREATER
            aes = new(
                key: key,
                tagSizeInBytes: tagSize);
#else
            aes = new(key: key);
#endif
        }

        /// <summary>
        /// Encrypts the plaintext into the ciphertext destination buffer and generates the authentication tag into a separate buffer.
        /// </summary>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="aad">Extra data that is NOT encrypted, but is authenticated via the tag. Must be present during encryption.</param>
        /// <returns>Ciphertext byte array with embedded header.</returns>
        public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad = default)
        {
            /// Read Header and allocate buffer, span regions
            var header = new DataCryptHeader()
            {
                Version = DataCrypt.Version,
                SaltSize = _salt?.Length ?? 0,
                NonceSize = AesGcm.NonceByteSizes.MaxSize,
                AadSize = aad.Length,
                TagSize = AesGcm.TagByteSizes.MaxSize,
                CiphertextSize = plaintext.Length
            };
            byte[] buffer = new byte[DataCryptHeader.Size + header.AadSize + header.SaltSize + header.NonceSize + header.TagSize + header.CiphertextSize];
            Span<byte> headerSpan = buffer.AsSpan(
                start: 0, 
                length: DataCryptHeader.Size);
            Span<byte> salt = buffer.AsSpan(
                start: headerSpan.Length,
                length: header.SaltSize);
            Span<byte> nonce = buffer.AsSpan(
                start: headerSpan.Length + salt.Length,
                length: header.NonceSize);
            Span<byte> userAad = buffer.AsSpan(
                start: headerSpan.Length + salt.Length + nonce.Length,
                length: header.AadSize);
            Span<byte> tag = buffer.AsSpan(
                start: headerSpan.Length + salt.Length + nonce.Length + userAad.Length,
                length: header.TagSize);
            Span<byte> ciphertext = buffer.AsSpan(
                start: headerSpan.Length + salt.Length + nonce.Length + userAad.Length + tag.Length,
                length: header.CiphertextSize);
            /// Fill Buffer
#pragma warning disable CS9191 // The 'ref' modifier for an argument corresponding to 'in' parameter is equivalent to 'in'. Consider using 'in' instead.
            MemoryMarshal.Write(
                destination: headerSpan, 
                value: ref header);
#pragma warning restore CS9191 // The 'ref' modifier for an argument corresponding to 'in' parameter is equivalent to 'in'. Consider using 'in' instead.
            aad.CopyTo(destination: userAad);
            _salt?.CopyTo(destination: salt);
            RandomNumberGenerator.Fill(data: nonce);
            /// Map authenticated regions
            ReadOnlySpan<byte> aadSpan = buffer.AsSpan(
                start: 0,
                length: headerSpan.Length + salt.Length + nonce.Length + userAad.Length);
            /// Encrypt and return buffer
            _aes.Encrypt(
                nonce: nonce,
                plaintext: plaintext,
                ciphertext: ciphertext,
                tag: tag,
                associatedData: aadSpan);
            return buffer;
        }

        /// <summary>
        /// Decrypts the ciphertext into the provided destination buffer if the authentication tag can be validated.
        /// </summary>
        /// <param name="ciphertext">Ciphertext with embedded header.</param>
        /// <param name="aad">Extra data that is NOT encrypted, but is authenticated via the tag. If there is none, this array will be empty.</param>
        /// <returns>Decrypted plaintext byte array.</returns>
        public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, out byte[] aad)
        {
            var header = MemoryMarshal.Read<DataCryptHeader>(ciphertext);
            if (header.Version != DataCrypt.Version)
            {
                throw new InvalidOperationException($"DataCrypt version mismatch. Please use DataCrypt 'Version {header.Version}' for this data.");
            }
            /// Slice Ciphertext into regions
            // Skip Salt -> This instance is already constructed with it so we don't care about it
            ReadOnlySpan<byte> nonce = ciphertext.Slice(
                start: DataCryptHeader.Size + header.SaltSize,
                length: header.NonceSize);
            ReadOnlySpan<byte> userAad = ciphertext.Slice(
                start: DataCryptHeader.Size + header.SaltSize + nonce.Length,
                length: header.AadSize);
            ReadOnlySpan<byte> tag = ciphertext.Slice(
                start: DataCryptHeader.Size + header.SaltSize + nonce.Length + userAad.Length,
                length: header.TagSize);
            ReadOnlySpan<byte> ciphertextSpan = ciphertext.Slice(
                start: DataCryptHeader.Size + header.SaltSize + nonce.Length + userAad.Length + tag.Length,
                length: header.CiphertextSize);
            /// Map authenticated regions
            ReadOnlySpan<byte> aadSpan = ciphertext.Slice(
                start: 0,
                length: DataCryptHeader.Size + header.SaltSize + nonce.Length + userAad.Length);
            /// Perform Decrypt and return Plaintext
            var plaintext = new byte[ciphertextSpan.Length];
            _aes.Decrypt(
                nonce: nonce,
                ciphertext: ciphertextSpan,
                tag: tag,
                plaintext: plaintext,
                associatedData: aadSpan);
            aad = userAad.ToArray();
            return plaintext;
        }

        /// <summary>
        /// Calculate the size of the Ciphertext based on input parameters.
        /// Should only be used prior to Encrypting.
        /// </summary>
        internal int CalculateCiphertextSize(int plaintextSize, int aadSize = 0)
        {
            return DataCryptHeader.Size + 
                (_salt?.Length ?? 0) + 
                AesGcm.NonceByteSizes.MaxSize + 
                aadSize + 
                AesGcm.TagByteSizes.MaxSize + 
                plaintextSize;
        }

        /// <summary>
        /// Extract the user provided 'associated data' (AAD) from the ciphertext.
        /// </summary>
        internal static ReadOnlySpan<byte> ExtractAad(FileStream ciphertext)
        {
            try
            {
                byte[] headerBytes = new byte[DataCryptHeader.Size];
                if (ciphertext.Read(headerBytes) != headerBytes.Length)
                {
                    throw new InvalidOperationException("Failed to read header.");
                }
                var header = MemoryMarshal.Read<DataCryptHeader>(headerBytes);
                if (header.Version != DataCrypt.Version)
                {
                    throw new InvalidOperationException($"DataCrypt version mismatch. Please use DataCrypt 'Version {header.Version}' for this data.");
                }
                var aad = new byte[header.AadSize];
                ciphertext.Seek(header.SaltSize + header.NonceSize, SeekOrigin.Current);
                if (ciphertext.Read(aad) != aad.Length)
                {
                    throw new InvalidOperationException("Failed to read AAD.");
                }
                return aad;
            }
            finally
            {
                ciphertext.Position = 0; // Reset position to the beginning of the stream
            }
        }

        private static byte[] DeriveKeyFromPassword(string password, ref ReadOnlySpan<byte> salt)
        {
            if (salt.IsEmpty)
                salt = RandomNumberGenerator.GetBytes(count: 16);
            return DataCryptInternal.DeriveKeyFromPassword(
                password: password,
                salt: salt);
        }

        public void Dispose()
        {
            _aes.Dispose();
        }
    }
}
