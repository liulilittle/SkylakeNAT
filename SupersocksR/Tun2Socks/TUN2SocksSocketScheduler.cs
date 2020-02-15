namespace SupersocksR.Tun2Socks
{
    using System;
    using System.Net;
    using SupersocksR.Net;
    using SupersocksR.Net.Entry;
    using AddressFamily = System.Net.Sockets.AddressFamily;

    public class TUN2SocksSocketScheduler : SocketScheduler
    {
        private readonly TUN2Socks m_tun2socks;

        public TUN2SocksSocketScheduler(TUN2Socks tun2socks, ILayerLocator locator) : base(locator)
        {
            this.m_tun2socks = tun2socks ?? throw new ArgumentNullException(nameof(tun2socks));
        }

        public override bool BeginAccept(IPcb pcb)
        {
            if (!base.BeginAccept(pcb))
            {
                return false;
            }

            IPEndPoint server = (IPEndPoint)pcb.RemoteEndPoint;
            if (IPEndPoint.MinPort >= server.Port || server.Port > IPEndPoint.MaxPort)
            {
                return false;
            }

            if (server.AddressFamily != AddressFamily.InterNetwork)
            {
                return false;
            }

            return true;
        }

        protected override Socket CreateSocket(IPcb pcb)
        {
            if (pcb == null)
            {
                return null;
            }
            return this.m_tun2socks.CreateSocket(pcb);
        }
    }
}
