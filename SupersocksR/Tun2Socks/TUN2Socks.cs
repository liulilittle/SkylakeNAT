namespace SupersocksR.Tun2Socks
{
    using System;
    using System.Linq;
    using System.Net;
    using SupersocksR.Net;
    using SupersocksR.Net.Entry;
    using SupersocksR.Net.Tun;

    public class TUN2Socks
    {
        private readonly Layer3Locator m_poLocator = null;
        private readonly PAC m_poPAC = null;
        private readonly Dnss m_poDNS = null;

        private class TUN2Layer3Locator : Layer3Locator
        {
            public TUN2Layer3Locator(TUN2Socks tun2socks, string componentId) : base(componentId)
            {
                this.Sockets = tun2socks.CreateSocketScheduler(this);
            }

            public override SocketScheduler Sockets { get; }
        }

        public TUN2Socks(EndPoint server)
        {
            this.m_poPAC = new PAC();
            this.m_poDNS = new Dnss(this, 53);
            this.Server = server ?? throw new ArgumentNullException(nameof(server));
            this.m_poLocator = new TUN2Layer3Locator(this, Layer3Netif.FindAllComponentId().FirstOrDefault());
        }

        public virtual Dnss GetDnss() => this.m_poDNS;

        public virtual PAC GetPAC() => this.m_poPAC;

        public virtual EndPoint Server { get; }

        public virtual void Run()
        {
            this.m_poPAC.Refresh();
            this.m_poDNS.Run();
            this.m_poLocator.Netif.Listen(new NetifConfiguration());
        }

        protected internal virtual TUN2SocksSocketScheduler CreateSocketScheduler(ILayerLocator locator)
        {
            return new TUN2SocksSocketScheduler(this, locator);
        }

        protected internal virtual TUN2SocksSocket CreateSocket(IPcb pcb)
        {
            return new TUN2SocksSocket(this, pcb);
        }

        public static void PrintTraceLine(string messasge)
        {
            Console.WriteLine($"[{DateTime.Now.ToString("HH:mm:ss")}] " + messasge);
        }
    }
}
