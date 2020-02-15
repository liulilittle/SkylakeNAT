namespace SupersocksR.Net.IP
{
    using SupersocksR.Core;
    using SupersocksR.Net.Icmp;
    using SupersocksR.Net.Tcp;
    using SupersocksR.Net.Udp;

    public interface IPLayer
    {
        TcpLayer Tcp { get; }

        UdpLayer Udp { get; }

        IcmpLayer Icmp { get; }

        void Output(IPFrame frame);

        void Input(IPFrame frame);

        IPFrame Parse(BufferSegment buffer);
    }
}
