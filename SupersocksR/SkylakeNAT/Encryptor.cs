namespace SupersocksR.SkylakeNAT
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.Text;
    using OpenSSL.Core;
    using OpenSSL.Crypto;
    using SupersocksR.Core;

    public unsafe class Encryptor : IDisposable
    {
        public readonly static string[] EncryptionNames = new[]
        {
            "aes-256-cfb",
            "aes-192-cfb",
            "aes-128-cfb",
            "bf-cfb"
        };

        public string method = EncryptionNames[0];
        public string password = string.Empty;
        public byte[] key = BufferSegment.Empty;
        private Cipher cipher = null;
        private IntPtr encryptCTX = IntPtr.Zero;
        private IntPtr decryptCTX = IntPtr.Zero;
        private byte[] iv = null;
        private readonly object LockObj = new object();
        private readonly static byte[] EmptyBuf = new byte[0];

        public void Dispose()
        {
            if (encryptCTX != IntPtr.Zero)
            {
                Native.EVP_CIPHER_CTX_cleanup(encryptCTX);
                Native.OPENSSL_free(encryptCTX);
                encryptCTX = IntPtr.Zero;
            }
            if (decryptCTX != IntPtr.Zero)
            {
                Native.EVP_CIPHER_CTX_cleanup(decryptCTX);
                Native.OPENSSL_free(decryptCTX);
                decryptCTX = IntPtr.Zero;
            }
        }

        ~Encryptor()
        {
            Dispose();
        }

        public Encryptor(string method, string password)
        {
            this.encryptCTX = IntPtr.Zero;
            this.decryptCTX = IntPtr.Zero;
            this.method = method;
            this.password = password;
            this.initKey(method, password);
        }

        private void initCipher(ref IntPtr ctx, byte[] iv, bool isCipher)
        {
            int enc = isCipher ? 1 : 0;
            if (ctx == IntPtr.Zero)
            {
                ctx = Native.OPENSSL_malloc(Marshal.SizeOf(typeof(CipherContext.EVP_CIPHER_CTX)));
                Native.EVP_CIPHER_CTX_init(ctx);
                Native.ExpectSuccess(Native.EVP_CipherInit_ex(ctx, this.cipher.Handle, IntPtr.Zero, null, null, enc));
                Native.ExpectSuccess(Native.EVP_CIPHER_CTX_set_key_length(ctx, key.Length));
                Native.ExpectSuccess(Native.EVP_CIPHER_CTX_set_padding(ctx, 1));
            }
            Native.ExpectSuccess(Native.EVP_CipherInit_ex(ctx, this.cipher.Handle, IntPtr.Zero, key, iv, enc));
        }

        private void initKey(string method, string password)
        {
            cipher = Cipher.CreateByName(method);
            if (cipher == null)
                throw new ArgumentOutOfRangeException("Such encryption cipher methods are not supported");

            byte[] passbuf = Encoding.Default.GetBytes(password);
            key = new byte[cipher.KeyLength];

            iv = new byte[cipher.IVLength];
            if (Native.EVP_BytesToKey(cipher.Handle, MessageDigest.MD5.Handle, null, passbuf, passbuf.Length, 1, key, iv) <= 0)
                throw new ExternalException("Bytes to key calculations cannot be performed using cipher with md5(md) key password iv key etc");

            int ivLen = cipher.IVLength;
            int md5len = ivLen < sizeof(Guid) ? sizeof(Guid) : ivLen;
            iv = new byte[ivLen]; // RAND_bytes(iv.get(), ivLen); = new byte[ivLen]; // RAND_bytes(iv.get(), ivLen);

            // MD5->RC4
            Buffer.BlockCopy(HashAlgorithm<MD5>.
                ComputeHash(
                    merges(
                        Encoding.Default.GetBytes($"SkylakeNAT@{method}."),
                        key,
                        Encoding.Default.GetBytes($".{password}"))), 0, iv, 0, sizeof(Guid));
            fixed (byte* piv = iv)
            fixed (byte* pkey = key)
                RC4.rc4_crypt(pkey, cipher.KeyLength, piv, ivLen, 0, 0);
        }

        private static byte[] merges(params byte[][] s)
        {
            if (s == null || s.Length <= 0)
                return BufferSegment.Empty;
            byte[] a = BufferSegment.Empty;
            foreach (byte[] i in s)
                a = merge(a, i);
            return a;
        }

        private static byte[] merge(byte[] a, byte[] b)
        {
            int al = a?.Length ?? 0;
            int bl = b?.Length ?? 0;
            int rl = al + bl;
            if (rl <= 0)
                return BufferSegment.Empty;
            byte[] r = new byte[rl];
            Buffer.BlockCopy(a, 0, r, 0, al);
            Buffer.BlockCopy(b, 0, r, al, bl);
            return r;
        }

        public virtual BufferSegment Encrypt(BufferSegment data)
        {
            lock (this.LockObj)
            {
                if (data == null || data.Length <= 0)
                {
                    return new BufferSegment(BufferSegment.Empty);
                }

                int outLen = data.Length + cipher.BlockSize;
                byte[] cipherText = new byte[outLen];
                fixed (byte* buf = &data.Buffer[data.Offset])
                {
                    // INIT-CTX
                    initCipher(ref encryptCTX, iv, true);
                    if (Native.EVP_CipherUpdate(encryptCTX, cipherText, out outLen, buf, data.Length) <= 0)
                    {
                        return new BufferSegment(BufferSegment.Empty);
                    }
                }
                return new BufferSegment(cipherText, outLen);
            }
        }

        public virtual BufferSegment Decrypt(BufferSegment data)
        {
            lock (this.LockObj)
            {
                if (data == null || data.Length <= 0)
                {
                    return new BufferSegment(BufferSegment.Empty);
                }
                
                int outLen = data.Length + cipher.BlockSize;
                byte[] cipherText = new byte[outLen];
                fixed (byte* buf = &data.Buffer[data.Offset])
                {
                    // INIT-CTX
                    initCipher(ref decryptCTX, iv, false);
                    if (Native.EVP_CipherUpdate(decryptCTX, cipherText, out outLen, buf, data.Length) <= 0)
                    {
                        return new BufferSegment(BufferSegment.Empty);
                    }
                }
                return new BufferSegment(cipherText, outLen);
            }
        }
    }
}
