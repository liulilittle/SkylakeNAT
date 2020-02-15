namespace SupersocksR.Net.Tcp
{
    using System.Net;
    using SupersocksR.Core;
    using SupersocksR.Net.Udp;

    public enum TcpFlags
    {
        TCP_FIN = 0x01,
        TCP_SYN = 0x02,
        TCP_RST = 0x04,
        TCP_PSH = 0x08,
        TCP_ACK = 0x10,
        TCP_UGR = 0x20,
        TCP_ECE = 0x40,
        TCP_CWR = 0x80,
        TCP_FLAGS = 0x3f
    }

    public class TcpFrame : UdpFrame
    {
        public static readonly BufferSegment Empty = new BufferSegment(BufferSegment.Empty);

        public virtual TcpFlags Flags { get; set; }

        public virtual uint SequenceNo { get; set; }

        public virtual uint AcknowledgeNo { get; set; }

        public virtual ushort WindowSize { get; set; }

        public virtual BufferSegment Options { get; set; }

        public virtual ushort UrgentPointer { get; set; }

        public TcpFrame(IPEndPoint source, IPEndPoint destination, BufferSegment payload) : base(source, destination, payload)
        {

        }
    }
}
