namespace SupersocksR.Net.Pptp
{
    using System;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;

    public class PptpRasdialClient
    {
        public ushort PeersCallId { get; set; }

        public ushort SelfCallId { get; set; }

        public int BindId { get; set; }

        public uint PhysicalChannelId { get; set; }

        public uint ReceiveBufferSize { get; set; }

        public uint MinBytesPerSecond { get; set; }

        public uint MaxBytesPerSecond { get; set; }

        public uint SendACCM { get; set; }

        public uint ReceiveACCM { get; set; }
    }

    public class PptpListener
    {
        private AsyncCallback m_pStartAcceptCallback;
        private Socket m_pServer;
        private int m_dwPCID = 1;

        public PptpListener()
        {
            m_pStartAcceptCallback = this.StartAcceptClient;
        }

        public virtual void Start()
        {
            if (m_pServer == null)
            {
                m_pServer = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                m_pServer.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                m_pServer.Bind(new IPEndPoint(IPAddress.Any, 1723));
                m_pServer.Listen(int.MaxValue);

                StartAcceptClient(null);
            }
        }

        private void StartAcceptClient(IAsyncResult ar)
        {
            if (ar == null)
            {
                m_pServer.BeginAccept(m_pStartAcceptCallback, null);
            }
            else
            {
                Socket socket = m_pServer.EndAccept(ar);
                Pptp client = new Pptp(this, socket);

                StartAcceptClient(null);
            }
        }

        public virtual PptpRasdialClient CreateClient()
        {
            PptpRasdialClient rasdial = new PptpRasdialClient();
            do
            {
                rasdial.PhysicalChannelId = (uint)Interlocked.Increment(ref m_dwPCID);
            } while (0 == rasdial.PhysicalChannelId);
            rasdial.SelfCallId = (ushort)rasdial.PhysicalChannelId;
            return rasdial;
        }
    }
}
