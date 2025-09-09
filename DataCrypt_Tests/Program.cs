using DataCrypt;
using DataCrypt.Common;
using DataCrypt.Core;
using System.Security.Cryptography;
using System.Text;

namespace DataCrypt_Tests
{
    internal class Program
    {
        static int Main()
        {
            Console.WriteLine($"Running Tests for DotNet {Environment.Version}");
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory); // Set working directory to the location of the executable
            Test_DataCryptKey();
            Test_DataCryptPassword();
            Test_DataCryptWithAad();
            Test_DataCryptWithSaltCtor();
            Test_AesStream();
            Test_FileCrypt();
            Console.WriteLine("All tests passed.");
            return 0;
        }

        private static void Test_DataCryptKey()
        {
            var key = RandomNumberGenerator.GetBytes(32);
            const string data = "Hello, World!";
            var ct = DataCrypt.DataCrypt.EncryptData(key, Encoding.UTF8.GetBytes(data));
            var pt = DataCrypt.DataCrypt.DecryptData(key, ct, out _);
            if (data != Encoding.UTF8.GetString(pt))
                throw new Exception("Test failed: Decrypted data does not match original.");
        }

        private static void Test_DataCryptPassword()
        {
            const string password = "Password123";
            const string data = "Hello, World!";
            var ct = DataCrypt.DataCrypt.EncryptData(password, Encoding.UTF8.GetBytes(data));
            var pt = DataCrypt.DataCrypt.DecryptData(password, ct, out _);
            if (data != Encoding.UTF8.GetString(pt))
                throw new Exception("Test failed: Decrypted data does not match original.");
        }

        private static void Test_DataCryptWithAad()
        {
            const string password = "Password123";
            const string data = "Hello, World!";
            var aad = RandomNumberGenerator.GetBytes(7);
            var ct = DataCrypt.DataCrypt.EncryptData(password, Encoding.UTF8.GetBytes(data), aad);
            var pt = DataCrypt.DataCrypt.DecryptData(password, ct, out var aadOut);
            if (data != Encoding.UTF8.GetString(pt))
                throw new Exception("Test failed: Decrypted data does not match original.");
            if (!aad.SequenceEqual(aadOut))
                throw new Exception("Test failed: AAD does not match original.");
        }

        private static void Test_DataCryptWithSaltCtor()
        {
            const string password = "Password123";
            const string data = "Hello, World!";
            byte[] ct, salt;
            {
                using var dc = new DataCryptContext(password: password);
                salt = dc.Salt.ToArray();
                ct = dc.Encrypt(
                    plaintext: Encoding.UTF8.GetBytes(data),
                    aad: RandomNumberGenerator.GetBytes(7));
            }
            byte[] pt;
            {
                using var dc = new DataCryptContext(
                    password: password,
                    salt: salt);
                pt = dc.Decrypt(
                    ciphertext: ct,
                    out var aadOut);
            }
            if (data != Encoding.UTF8.GetString(pt))
                throw new Exception("Test failed: Decrypted data does not match original.");
        }

        private static void Test_AesStream()
        {
            const string password = "Password123";
            byte[] data = new byte[] { 0xfa, 0xa4, 0x2a, 0x5e, 0x88, 0xf5, 0x7b, 0xe5, 0xaf, 0xf9 }; // Random bytes
                                                                                                     // Encrypt
            using var msEncrypt = new MemoryStream();
            ReadOnlySpan<byte> iv, salt;
            using (var encryptStream = new Aes256CbcStream(
                stream: msEncrypt,
                password: password,
                cryptoMode: CryptoMode.Encrypt,
                streamMode: CryptoStreamMode.Write))
            {
                iv = encryptStream.IV.Span;
                salt = encryptStream.Salt.Span;
                encryptStream.Write(data);
            }
            byte[] encrypted = msEncrypt.ToArray();

            // Decrypt
            using var msDecrypt = new MemoryStream(encrypted);
            using var decryptStream = new Aes256CbcStream(
                stream: msDecrypt,
                password: password,
                cryptoMode: CryptoMode.Decrypt,
                streamMode: CryptoStreamMode.Read,
                leaveOpen: false,
                iv: iv,
                salt: salt);

            byte[] decrypted = new byte[data.Length];
            int bytesRead = decryptStream.Read(decrypted, 0, decrypted.Length);

            if (!decrypted.SequenceEqual(data))
                throw new Exception("Test failed: Decrypted data does not match original.");
        }

        private static void Test_FileCrypt()
        {
            const string password = "Password123";
            const string data = "Hello, World!";
            const string source = "Test_FileCrypt.txt";
            const string dest = source + ".encrypted";
            File.WriteAllText(source, data);
            FileCrypt.EncryptFileToDisk(
                password: password,
                sourceFile: source,
                destFile: dest);
            using var pt = new MemoryStream();
            FileCrypt.DecryptFile(
                password: password,
                sourceFile: dest,
                destination: pt);
            if (data != Encoding.UTF8.GetString(pt.ToArray()))
                throw new Exception("Test failed: Decrypted data does not match original.");
        }
    }
}
