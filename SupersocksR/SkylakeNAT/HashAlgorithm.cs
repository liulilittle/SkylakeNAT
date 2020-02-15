namespace SupersocksR.SkylakeNAT
{
    using System;
    using System.Reflection;
    using System.Text;
    using SupersocksR.Core;

    public static class HashAlgorithm<T> where T : System.Security.Cryptography.HashAlgorithm
    {
        private static Func<T> CreateInstance = null;
        private static readonly object Look = new object();

        public static byte[] ComputeHash(byte[] buffer) => ComputeHash(buffer, buffer?.Length ?? 0);

        public static byte[] ComputeHash(byte[] buffer, int length)
        {
            if (buffer == null || buffer.Length <= 0)
            {
                return BufferSegment.Empty;
            }
            return ComputeHash(buffer, 0, length);
        }

        public static byte[] ComputeHash(byte[] buffer, int offset, int length)
        {
            if (buffer == null || buffer.Length <= 0)
            {
                return BufferSegment.Empty;
            }
            lock (Look)
            {
                if (CreateInstance == null)
                {
                    CreateInstance = (Func<T>)typeof(Func<T>).GetConstructors()[0].Invoke(new object[]
                    {
                        null,
                        typeof(T).GetMethod("Create", BindingFlags.Public | BindingFlags.Static, Type.DefaultBinder, Type.EmptyTypes, null).MethodHandle.GetFunctionPointer()
                    });
                }
            }
            using (T hash = CreateInstance())
            {
                try
                {
                    return hash.ComputeHash(buffer, offset, length);
                }
                catch (Exception)
                {
                    return BufferSegment.Empty;
                }
            }
        }

        public static string ToString(byte[] buffer, int offset, int length)
        {
            buffer = ComputeHash(buffer, offset, length);
            if (buffer == null || buffer.Length <= 0)
            {
                return string.Empty;
            }
            string message = string.Empty;
            for (int i = 0; i < buffer.Length; i++)
            {
                message += buffer[i].ToString("X2");
            }
            return message;
        }

        public static string ToString(string value, Encoding encoding)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }
            byte[] bytes = encoding.GetBytes(value);
            return ToString(bytes, 0, bytes.Length);
        }

        public static string ToString(string value)
        {
            return ToString(value, Encoding.UTF8);
        }
    }
}
