namespace SupersocksR.Net.Udp
{
    using System;
    using System.Net;
    using System.Net.Sockets;
    using SupersocksR.Core;
    using SupersocksR.Net.IP;
    using PcapDotNet.Packets.Ethernet;

    public class UdpFrame
    {
        public virtual IPEndPoint Source { get; set; }

        public virtual IPEndPoint Destination { get; set; }

        public virtual AddressFamily AddressFamily { get; }

        public virtual BufferSegment Payload { get; }

        public virtual int Ttl { get; set; }
 
        public virtual MacAddress SourceMacAddress { get; set; }

        public virtual MacAddress DestinationMacAddress { get; set; }

        public UdpFrame(IPEndPoint source, IPEndPoint destination, BufferSegment payload)
        {
            this.Ttl = IPFrame.DefaultTtl;
            this.Source = source ?? throw new ArgumentNullException(nameof(source));
            this.Destination = destination ?? throw new ArgumentNullException(nameof(Destination));
            this.AddressFamily = destination.AddressFamily;
            if (source.AddressFamily != destination.AddressFamily)
            {
                throw new ArgumentOutOfRangeException("The original address is inconsistent with the target address protocol.");
            }
            this.Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        }

        public override string ToString()
        {
            return string.Format($"{Source} -> {Destination}");
        }
    }
}
