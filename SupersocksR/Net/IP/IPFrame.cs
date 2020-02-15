namespace SupersocksR.Net.IP
{
    using System;
    using System.Net;
    using System.Net.Sockets;
    using SupersocksR.Core;
    using PcapDotNet.Packets.Ethernet;

    public enum IPFlags : ushort
    {
        IP_RF = 0x8000,        /* reserved fragment flag */
        IP_DF = 0x4000,        /* dont fragment flag */
        IP_MF = 0x2000,        /* more fragments flag */
        IP_OFFMASK = 0x1fff,   /* mask for fragmenting bits */
    }

    public unsafe class IPFrame
    {
        public const int DefaultTtl = 64;

        public IPFrame(ProtocolType protocolType, IPAddress source, IPAddress destination, BufferSegment payload)
        {
            this.Destination = destination ?? throw new ArgumentNullException(nameof(destination));
            this.Source = source ?? throw new ArgumentNullException(nameof(source));
            this.AddressFamily = destination.AddressFamily;
            if (source.AddressFamily != destination.AddressFamily)
            {
                throw new ArgumentOutOfRangeException("The original address is inconsistent with the target address protocol.");
            }
            this.Ttl = DefaultTtl;
            this.Tos = IPv4Layer.TOS_ROUTIN_MODE;
            this.Flags = IPFlags.IP_DF;
            this.ProtocolType = protocolType;
            this.Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        }

        public virtual AddressFamily AddressFamily { get; }

        public virtual ushort Id { get; set; }

        public virtual IPFlags Flags { get; set; }

        public virtual IPAddress Source { get; }

        public virtual IPAddress Destination { get; }

        public static uint GetAddressV4(IPAddress address)
        {
            if (address == null || address.AddressFamily != AddressFamily.InterNetwork)
            {
                return 0;
            }

            byte[] addressBytes = address.GetAddressBytes();
            fixed (byte* p = addressBytes)
            {
                if (p == null)
                {
                    return 0;
                }

                return *(uint*)p;
            }
        }

        public virtual uint SourceAddressV4
        {
            get
            {
                return GetAddressV4(this.Source);
            }
        }

        public virtual uint DestinationAddressV4
        {
            get
            {
                return GetAddressV4(this.Destination);
            }
        }

        public virtual MacAddress SourceMacAddress { get; set; }

        public virtual MacAddress DestinationMacAddress { get; set; }

        public virtual BufferSegment Payload { get; }

        public virtual BufferSegment Options { get; set; }

        public virtual int Ttl { get; set; }

        public virtual byte Tos { get; set; }

        public virtual ProtocolType ProtocolType { get; }

        public override string ToString()
        {
            if (0 == this.SourceMacAddress.ToValue())
            {
                return string.Format($"{this.Source} -> {this.Destination}");
            }
            else
            {
                return string.Format($"[{this.SourceMacAddress}] {this.Source} -> {this.Destination} [{this.DestinationMacAddress}]");
            }
        }
    }
}
