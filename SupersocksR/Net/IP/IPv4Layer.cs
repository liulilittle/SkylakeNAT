namespace SupersocksR.Net.IP
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Threading;
    using SupersocksR.Core;
    using SupersocksR.Net.Entry;
    using SupersocksR.Net.Icmp;
    using SupersocksR.Net.Tcp;
    using SupersocksR.Net.Udp;

    public unsafe class IPv4Layer : IPLayer
    {
        private static volatile int _locationId = Environment.TickCount;

        public virtual TcpLayer Tcp { get; }

        public virtual UdpLayer Udp { get; }

        public virtual IcmpLayer Icmp { get; }

        public virtual ILayerLocator Locator { get; }

        public IPv4Layer(ILayerLocator locator)
        {
            this.Locator = locator ?? throw new ArgumentNullException(nameof(locator));
            this.Tcp = locator.Tcp;
            this.Udp = locator.Udp;
            this.Icmp = locator.Icmp;
        }

        public virtual void Output(IPFrame frame)
        {
            var packet = ToArray(frame);
            if (packet != null)
            {
                Locator.Netif.Output(packet);
            }
        }

        public virtual void Input(IPFrame frame)
        {
            if (frame.ProtocolType == ProtocolType.Tcp)
            {
                var f = Tcp.Parse(frame);
                if (f != null)
                {
                    Tcp.Input(f);
                }
            }
            else if (frame.ProtocolType == ProtocolType.Udp)
            {
                var f = Udp.Parse(frame);
                if (f != null)
                {
                    Udp.Input(f);
                }
            }
            else if (frame.ProtocolType == ProtocolType.Icmp)
            {
                var f = Icmp.Parse(frame);
                if (f != null)
                {
                    Icmp.Input(f);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 20)]
        private struct ip_hdr
        {
#pragma warning disable 0649
            /* version / header length / type of service */
            public byte _v_hl;
            /* type of service */
            public byte _tos;
            /* total length */
            public ushort _len;
            /* identification */
            public ushort _id;
            /* fragment offset field */
            public ushort _flags;
            /* time to live */
            public byte _ttl;
            /* protocol */
            public byte _proto;
            /* checksum */
            public ushort _chksum;
            /* source and destination IP addresses */
            public uint src;
            public uint dest;
#pragma warning restore 0649

            public static int IPH_V(ip_hdr* hdr)
            {
                return ((hdr)->_v_hl >> 4);
            }

            public static int IPH_HL(ip_hdr* hdr)
            {
                return ((hdr)->_v_hl & 0x0f);
            }

            public static int IPH_PROTO(ip_hdr* hdr)
            {
                return ((hdr)->_proto & 0xff);
            }

            public static int IPH_OFFSET(ip_hdr* hdr)
            {
                return (hdr)->_flags;
            }

            public static int IPH_TTL(ip_hdr* hdr)
            {
                return ((hdr)->_ttl & 0xff);
            }
        }

        private const uint IP_ADDR_ANY_VALUE = 0x00000000;
        private const uint IP_ADDR_BROADCAST_VALUE = 0xffffffff;

        private static bool ip_addr_isbroadcast(uint addr)
        {
            /* all ones (broadcast) or all zeroes (old skool broadcast) */
            if ((~addr == IP_ADDR_ANY_VALUE) ||
                (addr == IP_ADDR_ANY_VALUE))
                return true;
            return false;
        }

        public const int IP_PROTO_ICMP = 1;
        public const int IP_PROTO_UDP = 17;
        public const int IP_PROTO_TCP = 6;
        public const int IP_PROTO_IGMP = 2;
        public const int IP_PROTO_GRE = 47;
        private const int IP_HLEN = 20;

        public virtual IPFrame Parse(BufferSegment buffer) => ParseFrame(buffer);

        public static IPFrame ParseFrame(BufferSegment packet, bool checksum = true)
        {
            if (packet == null)
            {
                return null;
            }
            IPFrame frame = null;
            packet.UnsafeAddrOfPinnedArrayElement((payload) =>
            {
                ip_hdr* iphdr = (ip_hdr*)payload;
                if (iphdr == null)
                {
                    return;
                }
                if (ip_hdr.IPH_V(iphdr) != 4)
                {
                    return;
                }
                int iphdr_hlen = ip_hdr.IPH_HL(iphdr) << 2;
                if (iphdr_hlen > packet.Length)
                {
                    return;
                }
                if (iphdr_hlen < IP_HLEN)
                {
                    return;
                }
                int ttl = ip_hdr.IPH_TTL(iphdr);
                if (ttl <= 0)
                {
                    return;
                }
                if (checksum && iphdr->_chksum != 0)
                {
                    int cksum = CheckSum.inet_chksum(iphdr, iphdr_hlen);
                    if (cksum != 0)
                    {
                        return;
                    }
                }
                if (ip_addr_isbroadcast(iphdr->src) || ip_addr_isbroadcast(iphdr->dest)) 
                {
                    return;
                }
                if ((ip_hdr.IPH_OFFSET(iphdr) & CheckSum.ntohs((ushort)(IPFlags.IP_OFFMASK | IPFlags.IP_MF))) != 0) // 不允许IP分片(NAT不太容易处理好分片)
                {
                    return;
                }
                ProtocolType protocolType = (ProtocolType)ip_hdr.IPH_PROTO(iphdr);
                if (protocolType == (ProtocolType)IP_PROTO_UDP ||
                    protocolType == (ProtocolType)IP_PROTO_TCP ||
                    protocolType == (ProtocolType)IP_PROTO_ICMP ||
                    protocolType == (ProtocolType)IP_PROTO_GRE)
                {
                    BufferSegment message_data = new BufferSegment(packet.Buffer, 
                        packet.Offset + iphdr_hlen, 
                        packet.Length - iphdr_hlen);
                    BufferSegment options_data = null;
                    int options_size = (iphdr_hlen - sizeof(ip_hdr));
                    if (options_size <= 0)
                    {
                        options_data = new BufferSegment(BufferSegment.Empty);
                    }
                    else
                    {
                        options_data = new BufferSegment(packet.Buffer,
                                packet.Offset + sizeof(ip_hdr), options_size);
                    }
                    frame = new IPFrame(protocolType,
                        new IPAddress(iphdr->src),
                        new IPAddress(iphdr->dest),
                        message_data)
                    {
                        Id = CheckSum.ntohs(iphdr->_id),
                        Ttl = ttl,
                        Tos = iphdr->_tos,
                        Options = options_data,
                        Flags = (IPFlags)CheckSum.ntohs(iphdr->_flags),
                    };
                }
            });
            return frame;
        }

        public const byte TOS_ROUTIN_MODE = 0x00;

        public static ushort NewId() => (ushort)Interlocked.Increment(ref _locationId);

        public static BufferSegment ToArray(IPFrame frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }
            BufferSegment payload_segment = frame.Payload;
            BufferSegment options_segment = frame.Options;
            int options_size = options_segment?.Length ?? 0;
            int payload_offset = sizeof(ip_hdr) + options_size;
            int payload_size = payload_segment?.Length ?? 0;
            byte[] message_data = new byte[payload_offset + payload_size];
            fixed (byte* pinned = message_data)
            {
                ip_hdr* iphdr = (ip_hdr*)pinned;
                iphdr->dest = frame.DestinationAddressV4;
                iphdr->src = frame.SourceAddressV4;
                iphdr->_ttl = (byte)frame.Ttl;
                iphdr->_proto = (byte)frame.ProtocolType;
                iphdr->_v_hl = (byte)(4 << 4 | payload_offset >> 2);
                iphdr->_tos = frame.Tos; // Routine Mode
                iphdr->_len = CheckSum.htons((ushort)message_data.Length);
                iphdr->_id = CheckSum.htons(frame.Id);
                iphdr->_flags = CheckSum.ntohs((ushort)frame.Flags);

                if (options_size > 0)
                {
                    IntPtr destination_options = (IntPtr)(pinned + sizeof(ip_hdr));
                    Marshal.Copy(options_segment.Buffer, options_segment.Offset, destination_options, options_size);
                }

                if (payload_size > 0)
                {
                    using (MemoryStream ms = new MemoryStream(message_data, payload_offset, payload_size))
                    {
                        ms.Write(payload_segment.Buffer, payload_segment.Offset, payload_size);
                    }
                }

                iphdr->_chksum = CheckSum.inet_chksum(pinned, payload_offset);
                if (iphdr->_chksum == 0)
                {
                    iphdr->_chksum = 0xffff;
                }
            }
            return new BufferSegment(message_data);
        }
    }
}
