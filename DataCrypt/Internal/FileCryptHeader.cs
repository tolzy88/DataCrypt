using System.Runtime.InteropServices;

namespace DataCrypt.Internal
{
    /// <summary>
    /// Header for FileCrypt format. Defines the size and layout of parameters.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal readonly struct FileCryptHeader
    {
        /// <summary>
        /// Size of the header.
        /// </summary>
        public static readonly int Size = Marshal.SizeOf<FileCryptHeader>();
        /// <summary>
        /// FileCrypt version number for this data.
        /// </summary>
        public readonly uint Version { get; init; } // Make sure this is *always* the first field in the struct
        /// <summary>
        /// Number of DataCrypt chunks in the FileCrypt data.
        /// </summary>
        public readonly int ChunkCount { get; init; }
        /// <summary>
        /// Size of each DataCrypt chunk.
        /// </summary>
        public readonly int ChunkSize { get; init; }
    }
}