using System;
using System.Runtime.InteropServices;

namespace Gibbed
{
    public static partial class XXTEA
    {
        public unsafe static byte[] Encrypt(
            byte[] dataBytes,
            int dataOffset,
            int dataCount,
            byte[] keyBytes,
            int keyOffset,
            int keyCount)
        {
            if (dataBytes == null)
            {
                throw new ArgumentNullException(nameof(dataBytes));
            }

            if (dataOffset < 0 || dataOffset >= dataBytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(dataOffset));
            }

            if (dataCount <= 0 || dataOffset + dataCount > dataBytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(dataCount));
            }

            if (keyBytes == null)
            {
                throw new ArgumentNullException(nameof(keyBytes));
            }

            if (keyOffset < 0 || keyOffset >= keyBytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(keyOffset));
            }

            if (keyCount <= 0 || keyOffset + keyCount > keyBytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(keyCount));
            }

            fixed (byte* dataBuffer = &dataBytes[dataOffset])
            fixed (byte* keyBuffer = &dataBytes[keyOffset])
            {
                var resultBytes = Native.Encrypt(dataBuffer, dataCount, keyBuffer, keyCount, out var resultCount);
                if (resultBytes != null && resultCount != resultBytes.Length)
                {
                    Array.Resize(ref resultBytes, resultCount);
                }
                return resultBytes;
            }
        }

        public unsafe static byte[] Decrypt(
            byte[] dataBytes,
            int dataOffset,
            int dataCount,
            byte[] keyBytes,
            int keyOffset,
            int keyCount)
        {
            if (dataBytes == null)
            {
                throw new ArgumentNullException(nameof(dataBytes));
            }

            if (dataOffset < 0 || dataOffset >= dataBytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(dataOffset));
            }

            if (dataCount <= 0 || dataOffset + dataCount > dataBytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(dataCount));
            }

            if (keyBytes == null)
            {
                throw new ArgumentNullException(nameof(keyBytes));
            }

            if (keyOffset < 0 || keyOffset >= keyBytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(keyOffset));
            }

            if (keyCount <= 0 || keyOffset + keyCount > keyBytes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(keyCount));
            }

            fixed (byte* dataBuffer = &dataBytes[dataOffset])
            fixed (byte* keyBuffer = &keyBytes[keyOffset])
            {
                var resultBytes = Native.Decrypt(dataBuffer, dataCount, keyBuffer, keyCount, out var resultCount);
                if (resultBytes != null && resultCount != resultBytes.Length)
                {
                    Array.Resize(ref resultBytes, resultCount);
                }
                return resultBytes;
            }
        }
    }
}
