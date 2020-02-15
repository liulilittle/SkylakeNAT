namespace SupersocksR.Net.Icmp
{
    using System;
    using System.Net;
    using System.Net.Sockets;
    using SupersocksR.Core;
    using SupersocksR.Net.IP;
    using PcapDotNet.Packets.Ethernet;

    public enum IcmpType : byte
    {
        ICMP_ER = 0,        /* echo reply */
        ICMP_DUR = 3,       /* destination unreachable */
        ICMP_SQ = 4,        /* source quench */
        ICMP_RD = 5,        /* redirect */
        ICMP_ECHO = 8,      /* echo */
        ICMP_TE = 11,       /* time exceeded */
        ICMP_PP = 12,       /* parameter problem */
        ICMP_TS = 13,       /* timestamp */
        ICMP_TSR = 14,      /* timestamp reply */
        ICMP_IRQ = 15,      /* information request */
        ICMP_IR = 16,       /* information reply */
        ICMP_AM = 17,       /* address mask request */
        ICMP_AMR = 18,      /* address mask reply */
    }

    public class IcmpFrame
    {
        public virtual IcmpType Type { get; set; }

        public virtual byte Code { get; set; }

        public virtual ushort Identification { get; set; }

        public virtual ushort Sequence { get; set; }

        public virtual IPAddress Source { get; }

        public virtual IPAddress Destination { get; }

        public virtual int Ttl { get; set; }

        public virtual AddressFamily AddressFamily { get; }

        public virtual BufferSegment Payload { get; set; }

        public virtual MacAddress SourceMacAddress { get; set; }

        public virtual MacAddress DestinationMacAddress { get; set; }

        public IcmpFrame(IPAddress source, IPAddress destination, BufferSegment payload)
        {
            this.Ttl = IPFrame.DefaultTtl;
            this.Payload = payload ?? new BufferSegment(BufferSegment.Empty);
            this.Source = source ?? throw new ArgumentNullException(nameof(source));
            this.Destination = destination ?? throw new ArgumentNullException(nameof(Destination));
            this.AddressFamily = destination.AddressFamily;
        }

        public override string ToString()
        {
            return string.Format($"{Source} -> {Destination}");
        }
    }
}
