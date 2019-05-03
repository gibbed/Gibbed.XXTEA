using System;
using System.Runtime.InteropServices;

namespace Gibbed
{
    public static partial class XXTEA
    {
        private static class Native
        {
            public unsafe static byte[] Encrypt(byte* data, int data_len, byte* key, int key_len, out int out_len)
            {
                if (key_len >= 16)
                {
                    return Encrypt(data, data_len, key, out out_len);
                }

                var key2_array = FixKeyLength(key, key_len);
                fixed (byte* key2 = key2_array)
                {
                    return Encrypt(data, data_len, key2, out out_len);
                }
            }

            public unsafe static byte[] Decrypt(byte* data, int data_len, byte* key, int key_len, out int out_len)
            {
                if (key_len >= 16)
                {
                    return Decrypt(data, data_len, key, out out_len);
                }

                var key2_array = FixKeyLength(key, key_len);
                fixed (byte* key2 = key2_array)
                {
                    return Decrypt(data, data_len, key2, out out_len);
                }
            }

            private unsafe static byte[] FixKeyLength(byte* key, int key_len)
            {
                var tmp = new byte[16];
                Marshal.Copy(new IntPtr(key), tmp, 0, key_len);
                return tmp;
            }

            public const uint Delta = 0x9E3779B9;

            private unsafe static uint* Encrypt(uint* data, int len, uint* key)
            {
                int n = len - 1;
                if (n < 1)
                {
                    return data;
                }
                uint z = data[n];
                uint q = 6u + 52u / ((uint)n + 1u);
                uint sum = 0u;
                while (0 < q--)
                {
                    sum += Delta;
                    uint e = sum >> 2 & 3u;
                    uint y;
                    int p;
                    for (p = 0; p < n; p++)
                    {
                        y = data[p + 1];
                        z = data[p] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z));
                    }
                    y = data[0];
                    z = data[n] += (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z));
                }
                return data;
            }

            private unsafe static uint* Decrypt(uint* data, int len, uint* key)
            {
                int n = len - 1;
                if (n < 1)
                {
                    return data;
                }
                uint y = data[0];
                uint q = 6u + 52u / ((uint)n + 1u);
                uint sum = q * Delta;
                while (sum != 0)
                {
                    uint e = sum >> 2 & 3u;
                    uint z;
                    int p;
                    for (p = n; p > 0; p--)
                    {
                        z = data[p - 1];
                        y = data[p] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z));
                    }
                    z = data[n];
                    y = data[0] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z));
                    sum -= Delta;
                }
                return data;
            }

            private unsafe static byte[] Encrypt(byte* data, int len, byte* key, out int out_len)
            {
                if (len <= 0)
                {
                    out_len = 0;
                    return null;
                }
                var v_array = ToUIntArray(data, len, true, out int v_len);
                var k_array = ToUIntArray(key, 16, false, out _);
                fixed (uint* v = v_array)
                fixed (uint* k = k_array)
                {
                    return ToByteArray(Encrypt(v, v_len, k), v_len, false, out out_len);
                }
            }

            private unsafe static byte[] Decrypt(byte* data, int len, byte* key, out int out_len)
            {
                if (len <= 0)
                {
                    out_len = 0;
                    return null;
                }
                var v_array = ToUIntArray(data, len, false, out int v_len);
                var k_array = ToUIntArray(key, 16, false, out _);
                fixed (uint* v = v_array)
                fixed (uint* k = k_array)
                {
                    return ToByteArray(Decrypt(v, v_len, k), v_len, true, out out_len);
                }
            }

            private unsafe static uint[] ToUIntArray(byte* data, int len, bool inc_len, out int out_len)
            {
                int i, n;
                n = len >> 2;
                n = (((len & 3) == 0) ? n : n + 1);
                uint[] result;
                if (inc_len == true)
                {
                    result = new uint[n + 1];
                    result[n] = (uint)len;
                    out_len = n + 1;
                }
                else
                {
                    result = new uint[n];
                    out_len = n;
                }
                for (i = 0; i < len; ++i)
                {
                    result[i >> 2] |= ((uint)data[i]) << ((i & 3) << 3);
                }
                return result;
            }

            private unsafe static byte[] ToByteArray(uint* data, int len, bool inc_len, out int out_len)
            {
                int i, n;
                uint m;
                n = len << 2;
                if (inc_len == true)
                {
                    m = data[len - 1];
                    n -= 4;
                    if ((m < n - 3) || (m > n))
                    {
                        out_len = 0;
                        return null;
                    }
                    n = (int)m;
                }
                var result = new byte[n];
                for (i = 0; i < n; ++i)
                {
                    result[i] = (byte)((data[i >> 2] >> ((i & 3) << 3)) & 0xFF);
                }
                out_len = n;
                return result;
            }
        }
    }
}
