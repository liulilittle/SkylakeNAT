namespace SupersocksR.Core
{
    using System;
    using System.IO;
    using System.Text;
    using System.Collections;
    using System.Collections.Generic;

    public unsafe class BufferSegment : EventArgs, IEnumerable<byte>
    {
        public new static readonly byte[] Empty = new byte[0];
        public static readonly IntPtr Null = IntPtr.Zero;

        public virtual byte[] Buffer { get; }

        public virtual int Offset { get; }

        public virtual int Length { get; }

        public BufferSegment(byte[] buffer) : this(buffer, buffer?.Length ?? 0)
        {

        }

        public BufferSegment(byte[] buffer, int length) : this(buffer, 0, length)
        {

        }

        public BufferSegment(byte[] buffer, int offset, int length)
        {
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }
            this.Buffer = buffer ?? Empty;
            if ((offset + length) > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("The offset and length overflow the size of the buffer.");
            }
            this.Offset = offset;
            this.Length = length;
        }

        public static implicit operator BufferSegment(byte[] b)
        {
            if (b == null)
            {
                return new BufferSegment(Empty);
            }
            return new BufferSegment(b);
        }

        public virtual ArraySegment<byte> ToArraySegment()
        {
            return new ArraySegment<byte>(this.Buffer, this.Offset, this.Length);
        }

        public virtual byte[] ToArray()
        {
            return ToArraySegment().ToArray();
        }

        public void CopyTo(byte[] destination)
        {
            ToArraySegment().CopyTo(destination, 0);
        }

        public virtual void CopyTo(byte[] destination, int destinationIndex)
        {
            ToArraySegment().CopyTo(destination, destinationIndex);
        }

        public virtual void CopyTo(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            stream.Write(this.Buffer, this.Offset, this.Length);
        }

        public IntPtr UnsafeAddrOfPinnedArrayElement()
        {
            return UnsafeAddrOfPinnedArrayElement(null);
        }

        public virtual IntPtr UnsafeAddrOfPinnedArrayElement(Action<IntPtr> callback)
        {
            IntPtr ptr = IntPtr.Zero;
            var buffer = this.Buffer;
            fixed (byte* pinned = buffer)
            {
                if (pinned != null)
                {
                    int num = (this.Offset + this.Length);
                    if (buffer.Length >= num)
                    {
                        ptr = (IntPtr)(pinned + this.Offset);
                    }
                }
                callback?.Invoke(ptr);
            }
            return ptr;
        }

        public override string ToString()
        {
            string s = string.Empty;
            UnsafeAddrOfPinnedArrayElement((p) =>
            {
                if (p == null)
                    s = null;
                else
                    s = new string((sbyte*)p, 0, this.Length, Encoding.Default);
            });
            return s;
        }

        public virtual IEnumerator GetEnumerator()
        {
            IEnumerable<byte> enumerator = this;
            return enumerator.GetEnumerator();
        }

        IEnumerator<byte> IEnumerable<byte>.GetEnumerator()
        {
            var offset = this.Offset;
            var size = this.Length;
            var pinned = this.Buffer;
            if (offset > 0 && size > 0)
            {
                for (int i = offset; i < size; i++)
                {
                    yield return pinned[i];
                }
            }
        }
    }

    public static class Extension
    {
        public static T[] ToArray<T>(this ArraySegment<T> segment)
        {
            T[] s = null;
            if (segment != null)
            {
                s = new T[segment.Count];
                CopyTo(segment, s, 0);
            }
            return s;
        }

        public static void CopyTo<T>(this ArraySegment<T> segment, T[] destination, int destinationIndex)
        {
            if (segment != null && destination != null && destinationIndex >= 0)
            {
                Buffer.BlockCopy(segment.Array, segment.Offset, destination, destinationIndex, segment.Count);
            }
        }

        public static bool Remove<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, out TValue value)
        {
            value = default(TValue);
            if (dictionary == null)
            {
                return false;
            }

            lock (dictionary)
            {
                if (!dictionary.TryGetValue(key, out value))
                {
                    return false;
                }

                return dictionary.Remove(key);
            }
        }

        public static bool TryAdd<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, TValue value)
        {
            if (dictionary == null)
            {
                return false;
            }

            lock (dictionary)
            {
                if (dictionary.ContainsKey(key))
                {
                    return false;
                }

                dictionary.Add(key, value);
            }
            return true;
        }
    }
}
