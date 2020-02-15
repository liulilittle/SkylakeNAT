namespace SupersocksR.Net.Entry
{
    using SupersocksR.Net;
    using SupersocksR.Net.Icmp;
    using SupersocksR.Net.IP;
    using SupersocksR.Net.Tcp;
    using SupersocksR.Net.Tun;
    using SupersocksR.Net.Udp;

    public interface ILayerLocator
    {
        TcpLayer Tcp { get; }

        UdpLayer Udp { get; }

        IcmpLayer Icmp { get; }

        INetif Netif { get; }

        IPLayer IPv4 { get; }

        SocketScheduler Sockets { get; }
    }
}
