namespace SupersocksR.Net
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Sockets;
    using SupersocksR.Core;
    using SupersocksR.Net.Tun;

    public abstract class IPcb
    {
        public event EventHandler<BufferSegment> Message;
        public event EventHandler Open;
        public event EventHandler Abort;

        public virtual AddressFamily AddressFamily { get; }

        public virtual EndPoint RemoteEndPoint { get; }

        public virtual EndPoint LocalEndPoint { get; }

        protected internal virtual void OnOpen(EventArgs e)
        {
            this.Open?.Invoke(this, e);
        }

        protected internal virtual void OnMessage(BufferSegment e)
        {
            this.Message?.Invoke(this, e);
        }

        protected internal virtual void OnAbort(EventArgs e)
        {
            this.Abort?.Invoke(this, e);
        }

        public abstract bool Send(BufferSegment buffer);

        public static IList<BufferSegment> Slices(BufferSegment buffer)
        {
            IList<BufferSegment> segments = new List<BufferSegment>();
            int payload_size = buffer.Length;
            int payload_offset = 0;
            while (payload_size > 0)
            {
                int segments_size = payload_size;
                if (segments_size > Layer3Netif.MSS)
                    segments_size = Layer3Netif.MSS;
                payload_size -= segments_size;

                segments.Add(new BufferSegment(buffer.Buffer, buffer.Offset + payload_offset, segments_size));
                payload_offset += segments_size;
            }
            return segments;
        }

        public abstract void Close();

        public virtual string PcbKey => $"{this.LocalEndPoint} -> {this.RemoteEndPoint}";
    }
}
