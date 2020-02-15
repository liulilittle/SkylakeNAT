namespace SupersocksR.SkylakeNAT
{
    public unsafe static class RC4
    {
        private static void rc4_sbox(byte* box, string key)
        {
            if (null == box || null == key || key.Length <= 0)
                return;

            for (int i = 0; i < 255; i++)
                box[i] = (byte)i;

            for (int i = 0, j = 0; i < 255; i++)
            {
                j = (j + box[i] + (byte)key[i % key.Length]) % 255;
                byte b = box[i];
                box[i] = box[j];
                box[j] = b;
            }
        }

        public static void rc4_crypt(string key, byte* data, int datalen, int subtract, int E)
        {
            if (null == key || key.Length <= 0 || null == data || datalen <= 0)
                return;

            byte* box = stackalloc byte[255];
            rc4_sbox(box, key);

            byte x = (byte)(0 != E ? subtract : -subtract);
            for (int i = 0, low = 0, high = 0, mid; i < datalen; i++)
            {
                low = low % 255;
                high = (high + box[i % 255]) % 255;

                byte b = box[low];
                box[low] = box[high];
                box[high] = b;

                mid = (box[low] + box[high]) % 255;
                if (0 != E)
                    data[i] = (byte)((data[i] ^ box[mid]) - x);
                else
                    data[i] = (byte)((data[i] - x) ^ box[mid]);
            }
        }

        private static void rc4_sbox(byte* box, byte* key, int keylen)
        {
            if (null == box || null == key || keylen <= 0)
                return;

            for (int i = 0; i < 255; i++)
                box[i] = (byte)i;

            for (int i = 0, j = 0; i < 255; i++)
            {
                j = (j + box[i] + (byte)key[i % keylen]) % 255;
                byte b = box[i];
                box[i] = box[j];
                box[j] = b;
            }
        }

        public static void rc4_crypt(byte* key, int keylen, byte* data, int datalen, int subtract, int E)
        {
            if (null == key || keylen <= 0 || null == data || datalen <= 0)
                return;

            byte* box = stackalloc byte[255];
            rc4_sbox(box, key, keylen);

            byte x = (byte)(0 != E ? subtract : -subtract);
            for (int i = 0, low = 0, high = 0, mid; i < datalen; i++)
            {
                low = low % 255;
                high = (high + box[i % 255]) % 255;

                byte b = box[low];
                box[low] = box[high];
                box[high] = b;

                mid = (box[low] + box[high]) % 255;
                if (0 != E)
                    data[i] = (byte)((data[i] ^ box[mid]) - x);
                else
                    data[i] = (byte)((data[i] - x) ^ box[mid]);
            }
        }
    }
}
