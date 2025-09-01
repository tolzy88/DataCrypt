using DataCrypt.Core;
using DataCrypt.Internal;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DataCrypt
{
    /// <summary>
    /// Static File encryption abstractions utilizing AES-256-GCM.
    /// </summary>
    public static class FileCrypt
    {
        /// <summary>
        /// The version of the FileCrypt format. If there are breaking changes this version will be incremented.
        /// </summary>
        public const uint Version = 8;

        /// <summary>
        /// Encrypt a file using AES-GCM-256.
        /// Writes file to disk.
        /// </summary>
        /// <param name="password">Password used to derive key. NOTE: FileCrypt will use key stretching on this password.</param>
        /// <param name="sourceFile">File to encrypt.</param>
        /// <param name="destFile">(Optional) Path to write to. By default will write to the same location with '.encrypted' appended.</param>
        public static void EncryptFileToDisk(string password, string sourceFile, string destFile = null)
        {
            destFile ??= sourceFile + ".encrypted";
            using (var fsOut = new FileStream(destFile, FileMode.Create, FileAccess.Write))
            {
                EncryptFile(password, sourceFile, fsOut);
            }
        }

        /// <summary>
        /// Encrypt a file using AES-GCM-256.
        /// </summary>
        /// <param name="password">Password used to derive key. NOTE: FileCrypt will use key stretching on this password.</param>
        /// <param name="sourceFile">File to encrypt from.</param>
        /// <returns>Byte array of encrypted file contents.</returns>
        public static byte[] EncryptFile(string password, string sourceFile)
        {
            using var ms = new MemoryStream();
            using (var fsIn = new FileStream(sourceFile, FileMode.Open, FileAccess.Read))
            {
                EncryptFile(password, sourceFile, ms);
            }
            return ms.ToArray();
        }

        /// <summary>
        /// Encrypt a file using AES-GCM-256.
        /// </summary>
        /// <param name="password">Password used to derive key. NOTE: FileCrypt will use key stretching on this password.</param>
        /// <param name="sourceFile">File to encrypt from.</param>
        /// <param name="destination">Destination stream to decrypt to. Must be writable.</param>
        public static void EncryptFile(string password, string sourceFile, Stream destination)
        {
            using (var fsIn = new FileStream(sourceFile, FileMode.Open, FileAccess.Read))
            {
                EncryptStream(fsIn, destination, password);
            }
        }

        private static void EncryptStream(FileStream sourceFile, Stream dest, string password)
        {
            // Parse chunk count
            const int baseChunkSize = 1073741824;
            int chunkCount = (int)Math.Ceiling((decimal)sourceFile.Length / (decimal)baseChunkSize);
            byte[] buffer = new byte[chunkCount == 1 ?
                sourceFile.Length : baseChunkSize];
            // Write Header
            using var context = new DataCryptContext(password: password);
            var header = new FileCryptHeader()
            {
                Version = Version,
                ChunkCount = chunkCount,
                ChunkSize = context.CalculateCiphertextSize(
                    plaintextSize: buffer.Length, 
                    aadSize: FileCryptHeader.Size)
            };
            var headerBytes = new byte[FileCryptHeader.Size];
#pragma warning disable CS9191 // The 'ref' modifier for an argument corresponding to 'in' parameter is equivalent to 'in'. Consider using 'in' instead.
            MemoryMarshal.Write(headerBytes, ref header);
#pragma warning restore CS9191 // The 'ref' modifier for an argument corresponding to 'in' parameter is equivalent to 'in'. Consider using 'in' instead.
            // Encrypt
            for (int i = 0; i < chunkCount; i++)
            {
                int cb = sourceFile.Read(buffer);
                var ciphertext = context.Encrypt(
                    plaintext: buffer.AsSpan(0, cb),
                    aad: i == 0 ? headerBytes : default);
                dest.Write(ciphertext);
            }
        }

        /// <summary>
        /// Decrypt a file using AES-GCM-256.
        /// Writes file to disk.
        /// </summary>
        /// <param name="password">Password used during encryption. NOTE: FileCrypt will use key stretching on this password.</param>
        /// <param name="sourceFile">File to decrypt.</param>
        /// <param name="destFile">(Optional) Path to write to. By default will write to the same location with '.decrypted' appended.</param>
        public static void DecryptFileToDisk(string password, string sourceFile, string destFile = null)
        {
            destFile ??= sourceFile + ".decrypted";
            using (var fsOut = new FileStream(destFile, FileMode.Create, FileAccess.Write))
            {
                DecryptFile(password, sourceFile, fsOut);
            }
        }

        /// <summary>
        /// Decrypt a file using AES-GCM-256.
        /// </summary>
        /// <param name="password">Password used during encryption. NOTE: FileCrypt will use key stretching on this password.</param>
        /// <param name="sourceFile">File to decrypt from.</param>
        /// <returns>Byte array of decrypted file contents.</returns>
        public static byte[] DecryptFile(string password, string sourceFile)
        {
            using var ms = new MemoryStream();
            using (var fsIn = new FileStream(sourceFile, FileMode.Open, FileAccess.Read))
            {
                DecryptFile(password, sourceFile, ms);
            }
            return ms.ToArray();
        }

        /// <summary>
        /// Decrypt a file using AES-GCM-256.
        /// </summary>
        /// <param name="password">Password used during encryption. NOTE: FileCrypt will use key stretching on this password.</param>
        /// <param name="sourceFile">File to decrypt from.</param>
        /// <param name="destination">Destination stream to decrypt to. Must be writable.</param>
        public static void DecryptFile(string password, string sourceFile, Stream destination)
        {
            using (var fsIn = new FileStream(sourceFile, FileMode.Open, FileAccess.Read))
            {
                DecryptStream(fsIn, destination, password);
            }
        }

        private static void DecryptStream(FileStream sourceFile, Stream dest, string password)
        {
            // Read header
            var headerBytes = DataCryptContext.ExtractAad(ciphertext: sourceFile);
            var header = MemoryMarshal.Read<FileCryptHeader>(headerBytes);
            if (header.Version != Version)
            {
                throw new InvalidOperationException($"FileCrypt version mismatch. Please use FileCrypt 'Version {header.Version}' for this file.");
            }
            byte[] buffer = new byte[header.ChunkSize];
            // Decrypt
            DataCryptContext context = null;
            try
            {
                for (int i = 0; i < header.ChunkCount; i++)
                {
                    int cb = sourceFile.Read(
                        buffer: buffer,
                        offset: 0,
                        count: i == 0 ? buffer.Length : buffer.Length - FileCryptHeader.Size);
                    var ciphertext = buffer.AsSpan(0, cb);
                    context ??= new DataCryptContext(
                        ciphertext: ciphertext,
                        password: password);
                    var plaintext = context.Decrypt(
                        ciphertext: ciphertext,
                        aad: out _);
                    dest.Write(plaintext);
                }
                if (sourceFile.Read(buffer) != 0)
                    throw new CryptographicException("Unexpected data found after payload.");
            }
            finally
            {
                context?.Dispose();
            }
        }
    }
}
