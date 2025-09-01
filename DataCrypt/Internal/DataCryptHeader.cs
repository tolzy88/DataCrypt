using System.Runtime.InteropServices;

namespace DataCrypt.Internal
{
    /// <summary>
    /// Header for AES-GCM encryption with DataCrypt. Defines the size and layout of parameters.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 4)] // Header->Salt->Nonce->Aad->Tag->Ciphertext
    internal readonly struct DataCryptHeader
    {
        /// <summary>
        /// Size of the header.
        /// </summary>
        public static readonly int Size = Marshal.SizeOf<DataCryptHeader>();
        /// <summary>
        /// DataCrypt version number for this data.
        /// </summary>
        public readonly uint Version { get; init; } // Make sure this is *always* the first field in the struct
        /// <summary>
        /// Size of the salt used for key stretching.
        /// </summary>
        public readonly int SaltSize { get; init; }
        /// <summary>
        /// Size of the nonce used for AES-GCM.
        /// </summary>
        public readonly int NonceSize { get; init; }
        /// <summary>
        /// Size of the user provided 'associatedData' used for AES-GCM.
        /// </summary>
        public readonly int AadSize { get; init; }
        /// <summary>
        /// Size of the tag used for AES-GCM.
        /// </summary>
        public readonly int TagSize { get; init; }
        /// <summary>
        /// Size of the ciphertext payload.
        /// </summary>
        public readonly int CiphertextSize { get; init; }
    }
}
