namespace SupersocksR.Net.Entry
{
    using SupersocksR.Net;
    using SupersocksR.Net.Icmp;
    using SupersocksR.Net.IP;
    using SupersocksR.Net.Tcp;
    using SupersocksR.Net.Tun;
    using SupersocksR.Net.Udp;

    public class Layer3Locator : ILayerLocator
    {
        public virtual TcpLayer Tcp { get; }

        public virtual UdpLayer Udp { get; }

        public virtual INetif Netif { get; }

        public virtual IPLayer IPv4 { get; }

        public virtual SocketScheduler Sockets { get; }

        public virtual IcmpLayer Icmp { get; }

        public Layer3Locator(string componentId)
        {
            this.Tcp = new TcpLayer(this);
            this.Udp = new UdpLayer(this);
            this.Icmp = new IcmpLayer(this);
            this.IPv4 = new IPv4Layer(this);
            this.Netif = new Layer3Netif(this, componentId);
            this.Sockets = new SocketScheduler(this);
        }
    }
}
