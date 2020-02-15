namespace SupersocksR.Net.Udp
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using SupersocksR.Core;
    using SupersocksR.Net.Entry;
    using SupersocksR.Net.IP;

    public unsafe class UdpLayer
    {
        public virtual ILayerLocator Locator { get; }

        public UdpLayer(ILayerLocator locator)
        {
            this.Locator = locator ?? throw new ArgumentNullException(nameof(locator));
        }

        public virtual void Input(UdpFrame frame)
        {
            Output(new UdpFrame(frame.Destination, frame.Source, frame.Payload) { Ttl = frame.Ttl }); 
        }

        public static IPFrame ToIPFrame(UdpFrame frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }
            if (frame.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentNullException("UDP frames of this address family type are not supported.");
            }
            if (frame.Payload.Length <= 0)
            {
                return null;
            }
            int offset = sizeof(udp_hdr);
            int payload_len = frame.Payload.Length;
            byte[] message = new byte[offset + payload_len];
            fixed (byte* pinned = message)
            {
                udp_hdr* udphdr = (udp_hdr*)pinned;
                udphdr->dest = CheckSum.htons((ushort)frame.Destination.Port);
                udphdr->src = CheckSum.htons((ushort)frame.Source.Port);
                udphdr->len = CheckSum.htons((ushort)message.Length);

                using (MemoryStream ms = new MemoryStream(message, offset, payload_len))
                {
                    ms.Write(frame.Payload.Buffer, frame.Payload.Offset, payload_len);
                }

                ushort pseudo_checksum = CheckSum.inet_chksum_pseudo(pinned,
                    (uint)ProtocolType.Udp,
                    (uint)message.Length,
                    IPFrame.GetAddressV4(frame.Source.Address),
                    IPFrame.GetAddressV4(frame.Destination.Address));
                if (pseudo_checksum == 0)
                {
                    pseudo_checksum = 0xffff;
                }

                udphdr->chksum = pseudo_checksum;
            }
            return new IPFrame(ProtocolType.Udp, frame.Source.Address, frame.Destination.Address, new BufferSegment(message))
            {
                Ttl = frame.Ttl,
                SourceMacAddress = frame.SourceMacAddress,
                DestinationMacAddress = frame.DestinationMacAddress,
            };
        }

        public virtual void Output(UdpFrame frame)
        {
            IPFrame ip = ToIPFrame(frame);
            if (ip != null)
            {
                Locator.IPv4.Output(ip);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct udp_hdr
        {
            public ushort src;
            public ushort dest;  /* src/dest UDP ports */
            public ushort len;
            public ushort chksum;
        }

        public virtual UdpFrame Parse(IPFrame ip) => ParseFrame(ip);

        public static UdpFrame ParseFrame(IPFrame ip, bool checksum = true)
        {
            if (ip == null)
            {
                return null;
            }

            UdpFrame frame = null;
            BufferSegment payload = ip.Payload;
            payload.UnsafeAddrOfPinnedArrayElement((p) =>
            {
                udp_hdr* udphdr = (udp_hdr*)p;
                if (udphdr == null)
                {
                    return;
                }

                if (payload.Length != CheckSum.ntohs(udphdr->len)) // 错误的数据报
                {
                    return;
                }

                int offset = sizeof(udp_hdr);
                int len = payload.Length - offset;
                if (len <= 0)
                {
                    return;
                }

                if (checksum && udphdr->chksum != 0)
                {
                    uint pseudo_checksum = CheckSum.inet_chksum_pseudo((byte*)p.ToPointer(),
                        (uint)ProtocolType.Udp,
                        (uint)payload.Length,
                        ip.SourceAddressV4,
                        ip.DestinationAddressV4);
                    if (pseudo_checksum != 0)
                    {
                        return;
                    }
                }

                BufferSegment message = new BufferSegment(payload.Buffer, payload.Offset + offset, len);
                frame = new UdpFrame(
                    new IPEndPoint(ip.Source, CheckSum.ntohs(udphdr->src)),
                    new IPEndPoint(ip.Destination, CheckSum.ntohs(udphdr->dest)), message)
                    {
                        Ttl = ip.Ttl,
                        SourceMacAddress = ip.SourceMacAddress,
                        DestinationMacAddress = ip.DestinationMacAddress
                    };
            });
            return frame;
        }
    }
}
