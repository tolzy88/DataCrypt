using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace DataCrypt.Internal
{
    internal static class DataCryptInternal
    {
        private const int KEY_SIZE = 32; // 256 Bits Key Size
        private const int MIN_SALT_SIZE = 8;
        private const int MIN_PASSWORD_LENGTH = 8;
        private const int PBKDF2_ITERATIONS = 600000; // Common industry standard at the moment (BitWarden,etc.)

        /// <summary>
        /// Derive an Encryption Key from a Password using PBKDF2 Key Stretching.
        /// </summary>
        /// <param name="password">Plaintext password to derive key from.</param>
        /// <param name="salt">Crypto-random salt used to derive unique key.</param>
        /// <returns>256 Bit (32 Byte) Cryptographically Strong Key</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] DeriveKeyFromPassword(string password, ReadOnlySpan<byte> salt)
        {
            ArgumentNullException.ThrowIfNull(password);
            if (password.Length < MIN_PASSWORD_LENGTH)
                throw new ArgumentOutOfRangeException(nameof(password), $"Password must be at least {MIN_PASSWORD_LENGTH} characters long.");
            if (salt.Length < MIN_SALT_SIZE)
                throw new ArgumentOutOfRangeException(nameof(salt), $"Salt must be at least {MIN_SALT_SIZE} bytes long.");
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            using var pbkdf2 = new Rfc2898DeriveBytes(
                password: passwordBytes,
                salt: salt.ToArray(),
                iterations: PBKDF2_ITERATIONS,
                hashAlgorithm: HashAlgorithmName.SHA512);
            return pbkdf2.GetBytes(cb: KEY_SIZE);
        }

        /// <summary>
        /// Throws an exception if the key is not the correct size, or is cryptographically weak.
        /// </summary>
        /// <param name="key">Key to validate.</param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="ArgumentException"></exception>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ThrowIfInvalidKey(ReadOnlySpan<byte> key)
        {
            if (key.Length != KEY_SIZE)
                throw new ArgumentOutOfRangeException(nameof(key), $"Key must be {KEY_SIZE} bytes long.");
            Span<byte> zeroes = stackalloc byte[KEY_SIZE];
            zeroes.Clear();
            if (key.SequenceEqual(zeroes))
                throw new ArgumentException("Key cannot be all zeroes.", nameof(key));
        }
    }
}
