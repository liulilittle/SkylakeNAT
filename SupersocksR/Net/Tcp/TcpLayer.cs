namespace SupersocksR.Net.Tcp
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Threading;
    using SupersocksR.Core;
    using SupersocksR.Net.Entry;
    using SupersocksR.Net.IP;

    class SegmentsContext
    {
        public uint AcknowledgeNo;
        public uint SequenceNo;
        public TcpFlags Flags;
        public uint Length;
        public int Retransmission;
        public int Counter;
        public Stopwatch Stopwatch;
        public TcpPcb Pcb;
        public bool Timeout;
        public BufferSegment Payload = TcpFrame.Empty;

        public TcpFrame CreateFrame(TcpPcb pcb)
        {
            return new TcpFrame(pcb.Destination, pcb.Source, this.Payload)
            {
                AcknowledgeNo = this.AcknowledgeNo,
                SequenceNo = this.SequenceNo,
                Flags = this.Flags,
                Ttl = pcb.Ttl,
                WindowSize = (ushort)pcb.ReceiveBufferSize,
            };
        }
    }

    public unsafe class TcpLayer
    {
        private ConcurrentDictionary<string, TcpPcb> _pcbTable = new ConcurrentDictionary<string, TcpPcb>();
        private bool _disposed = false;

        /*
         * typedef struct _tcp_hdr  
         * {  
         *     unsigned short src_port;    //源端口号   
         *     unsigned short dst_port;    //目的端口号   
         *     unsigned int seq_no;        //序列号   
         *     unsigned int ack_no;        //确认号   
         *     #if LITTLE_ENDIAN   
         *     unsigned char reserved_1:4; //保留6位中的4位首部长度   
         *     unsigned char thl:4;        //tcp头部长度   
         *     unsigned char flag:6;       //6位标志   
         *     unsigned char reseverd_2:2; //保留6位中的2位   
         *     #else   
         *     unsigned char thl:4;        //tcp头部长度   
         *     unsigned char reserved_1:4; //保留6位中的4位首部长度   
         *     unsigned char reseverd_2:2; //保留6位中的2位   
         *     unsigned char flag:6;       //6位标志    
         *     #endif   
         *     unsigned short wnd_size;    //16位窗口大小   
         *     unsigned short chk_sum;     //16位TCP检验和   
         *     unsigned short urgt_p;      //16为紧急指针   
         * }tcp_hdr;  
         */

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct tcp_hdr
        {
            public ushort src;
            public ushort dest;
            public uint seqno;
            public uint ackno;
            public ushort _hdrlen_rsvd_flags;
            public ushort wnd;
            public ushort chksum;
            public ushort urgp; // 应用层不可能出现“URGP/UGR or OPT”的协议；这类紧急协议数据报文直接RST链接即可。
        }

        private const int TCP_HLEN = 20;

        private static ushort TCPH_HDRLEN(tcp_hdr* phdr)
        {
            return ((ushort)(CheckSum.ntohs((phdr)->_hdrlen_rsvd_flags) >> 12));
        }

        private static byte TCPH_HDRLEN_BYTES(tcp_hdr* phdr)
        {
            return ((byte)(TCPH_HDRLEN(phdr) << 2));
        }

        private static byte TCPH_FLAGS(tcp_hdr* phdr)
        {
            return ((byte)((CheckSum.ntohs((phdr)->_hdrlen_rsvd_flags) & (byte)TcpFlags.TCP_FLAGS)));
        }

        private static ushort TCPH_HDRLEN_SET(tcp_hdr* phdr, int len)
        {
            var u = ((len) << 12) | TCPH_FLAGS(phdr);
            return (phdr)->_hdrlen_rsvd_flags = CheckSum.htons((ushort)u);
        }

        private static ushort PP_HTONS(int x)
        {
            return ((ushort)((((x) & (ushort)0x00ffU) << 8) | (((x) & (ushort)0xff00U) >> 8)));
        }

        private static ushort TCPH_FLAGS_SET(tcp_hdr* phdr, int flags)
        {
            return (phdr)->_hdrlen_rsvd_flags = (ushort)(((phdr)->_hdrlen_rsvd_flags &
                PP_HTONS(~(ushort)TcpFlags.TCP_FLAGS)) | CheckSum.htons((ushort)flags));
        }

        public virtual ILayerLocator Locator { get; }

        public TcpLayer(ILayerLocator locator)
        {
            this.Locator = locator ?? throw new ArgumentNullException(nameof(locator));
            new Thread(WorkThread) { IsBackground = true, Priority = ThreadPriority.Lowest }.Start();
        }

        private void WorkThread(object state)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            while (!this._disposed)
            {
                if (stopwatch.ElapsedTicks < TcpPcb.MIN_RTO)
                {
                    Thread.Sleep(1);
                    continue;
                }
                else
                {
                    stopwatch.Restart();
                }

                foreach (var pair in _pcbTable)
                {
                    TcpPcb pcb = pair.Value;
                    if (pcb == null)
                    {
                        continue;
                    }

                    SortedDictionary<long, SegmentsContext> segments = pcb.SegmentsContexts;
                    if (segments == null)
                    {
                        continue;
                    }

                    lock (segments)
                    {
                        var remove_segments_keys = new List<long>();
                        foreach (var segments_pair in segments)
                        {
                            SegmentsContext segments_context = segments_pair.Value;
                            if (segments_context == null)
                            {
                                continue;
                            }

                            double rto_radix = Math.Pow(1.5, Math.Min(segments_context.Retransmission, (1 + segments_context.Counter)));
                            if (segments_context.Stopwatch.ElapsedMilliseconds >= (Math.Max(pcb.RTO, TcpPcb.MIN_RTO)
                                * rto_radix))
                            {
                                if (segments_context.Counter++ < segments_context.Retransmission)
                                {
                                    segments_context.Stopwatch.Restart();
                                    this.Output(segments_context.CreateFrame(pcb));
                                }
                                else
                                {
                                    remove_segments_keys.Add(segments_pair.Key);
                                }
                            }
                        }

                        foreach (var segments_key in remove_segments_keys)
                        {
                            pcb.SegmentsContexts.Remove(segments_key, out SegmentsContext segments_x);
                        }
                    }
                }

            }
        }

        private void ClosePCB(TcpPcb pcb, TcpState state)
        {
            if (pcb == null)
            {
                return;
            }
            string pcbKey = GetPcbKey(pcb.Source, pcb.Destination);
            lock (_pcbTable)
            {
                _pcbTable.TryRemove(pcbKey, out TcpPcb pcbx);
            }
            lock (pcb)
            {
                pcb.State = state;
                if (!pcb.Aborted)
                {
                    pcb.Aborted = true;
                    pcb.OnAbort(EventArgs.Empty);
                }
            }
        }

        private static string GetPcbKey(IPEndPoint source, IPEndPoint destination)
        {
            string key = $"{source} <-> {destination}";
            return key;
        }

        private void RST(TcpPcb pcb, TcpFrame frame)
        {
            uint seqno = frame.AcknowledgeNo;
            uint ackno = frame.SequenceNo + 1;
            pcb.State = TcpState.LAST_ACK;
            pcb.Post(TcpFlags.TCP_RST, ackno, seqno);
            ClosePCB(pcb, TcpState.CLOSED);
        }

        public virtual void Input(TcpFrame frame)
        {
            string pcbKey = GetPcbKey(frame.Source, frame.Destination);
            TcpPcb pcb = null;
            lock (_pcbTable)
            {
                _pcbTable.TryGetValue(pcbKey, out pcb);
                if (pcb == null)
                {
                    pcb = new TcpPcb(frame, this.Locator)
                    {
                        State = TcpState.SYN_RCVD
                    };
                    if (0 == (frame.Flags & TcpFlags.TCP_SYN) || // 不接受此套接字则积极拒绝
                        !this.Locator.Sockets.BeginAccept(pcb))
                    {
                        RST(pcb, frame);
                        return;
                    }

                    _pcbTable.TryAdd(pcbKey, pcb);
                    pcb.Open += (sender, e) =>
                    {
                        if (!pcb.Estableshed)
                        {
                            pcb.Estableshed = true;
                            var socket = this.Locator.Sockets.EndAccept(pcb);
                            if (socket == null)
                            {
                                pcb.Close();
                            }
                            else
                            {
                                pcb.OnOpen(e);
                            }
                        }
                    };
                    pcb.Abort += (sender, e) => ClosePCB(sender as TcpPcb, TcpState.CLOSED);
                }
            }
            lock (pcb)
            {
                if (0 != (frame.Flags & TcpFlags.TCP_SYN))
                {
                    uint seqno = pcb.AcknowledgeNo++;
                    uint ackno = ++pcb.SequenceNo;
                    pcb.Post(TcpFlags.TCP_SYN | TcpFlags.TCP_ACK, ackno, seqno, 1, 3);
                }
                else if (0 != (frame.Flags & TcpFlags.TCP_RST) ||
                    0 != (frame.Flags & (TcpFlags.TCP_CWR | TcpFlags.TCP_ECE | TcpFlags.TCP_UGR)))
                {
                    RST(pcb, frame);
                }
                else
                {
                    pcb.SendBufferSize = frame.WindowSize;
                    if (0 != (frame.Flags & TcpFlags.TCP_ACK))
                    {
                        pcb.Ack(frame.AcknowledgeNo);
                    }

                    if (0 != (frame.Flags & TcpFlags.TCP_PSH))
                    {
                        uint pylen = (uint)frame.Payload.Length;
                        uint seqno = frame.AcknowledgeNo;
                        uint ackno = frame.SequenceNo + pylen;

                        if (ackno >= pcb.SequenceNo)
                        {
                            pcb.InputStream.Input(frame);
                        }
                        else
                        {
                            pcb.Post(TcpFlags.TCP_ACK, ackno, seqno, 0);
                        }
                    }
                    else if (0 != (frame.Flags & TcpFlags.TCP_FIN))
                    {
                        uint seqno = frame.AcknowledgeNo;
                        uint ackno = frame.SequenceNo + 1;

                        pcb.Post(TcpFlags.TCP_ACK, ackno, seqno, 0);
                        ClosePCB(pcb, TcpState.CLOSED);
                    }
                }
            }
        }

        public virtual void Output(TcpFrame frame)
        {
            IPFrame ip = ToIPFrame(frame);
            if (ip != null)
            {
                Locator.IPv4.Output(ip);
            }
        }

        public static IPFrame ToIPFrame(TcpFrame frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }

            if (frame.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentNullException("TCP frames of this address family type are not supported.");
            }

            BufferSegment options_data = frame.Options;
            int options_size = options_data?.Length ?? 0;
            int payload_offset = sizeof(tcp_hdr) + options_size;
            int payload_size = frame.Payload?.Length ?? 0;

            byte[] message = new byte[payload_offset + payload_size];
            fixed (byte* pinned = message)
            {
                tcp_hdr* tcphdr = (tcp_hdr*)pinned;
                tcphdr->dest = CheckSum.htons((ushort)frame.Destination.Port);
                tcphdr->src = CheckSum.htons((ushort)frame.Source.Port);
                tcphdr->seqno = CheckSum.htonl(frame.SequenceNo);
                tcphdr->ackno = CheckSum.htonl(frame.AcknowledgeNo);
                tcphdr->urgp = CheckSum.htons(frame.UrgentPointer);
                tcphdr->wnd = CheckSum.htons(frame.WindowSize);

                TCPH_HDRLEN_SET(tcphdr, payload_offset >> 2);
                TCPH_FLAGS_SET(tcphdr, (int)frame.Flags);

                if (options_size > 0)
                {
                    IntPtr destination_options = (IntPtr)(pinned + sizeof(tcp_hdr));
                    Marshal.Copy(options_data.Buffer, options_data.Offset, destination_options, options_size);
                }

                if (payload_size > 0)
                {
                    using (MemoryStream ms = new MemoryStream(message, payload_offset, payload_size))
                    {
                        ms.Write(frame.Payload.Buffer, frame.Payload.Offset, payload_size);
                    }
                }

                ushort pseudo_checksum = CheckSum.inet_chksum_pseudo(pinned, (uint)ProtocolType.Tcp, (uint)message.Length,
                        IPFrame.GetAddressV4(frame.Source.Address),
                        IPFrame.GetAddressV4(frame.Destination.Address));
                if (pseudo_checksum == 0)
                {
                    pseudo_checksum = 0xffff;
                }

                tcphdr->chksum = pseudo_checksum;
            }

            return new IPFrame(ProtocolType.Tcp, frame.Source.Address, frame.Destination.Address, new BufferSegment(message))
            {
                Ttl = frame.Ttl,
                SourceMacAddress = frame.SourceMacAddress,
                DestinationMacAddress = frame.DestinationMacAddress,
            };
        }

        public static TcpFrame ParseFrame(IPFrame ip, bool checksum = true)
        {
            if (ip == null)
            {
                return null;
            }

            TcpFrame frame = null;
            BufferSegment packet = ip.Payload;
            packet.UnsafeAddrOfPinnedArrayElement((p) =>
            {
                tcp_hdr* tcphdr = (tcp_hdr*)p;
                if (tcphdr == null)
                {
                    return;
                }

                int hdrlen_bytes = TCPH_HDRLEN_BYTES(tcphdr);
                if (hdrlen_bytes < TCP_HLEN || hdrlen_bytes > packet.Length) // 错误的数据报
                {
                    return;
                }

                int len = packet.Length - hdrlen_bytes;
                if (len < 0)
                {
                    return;
                }

                TcpFlags flags = (TcpFlags)TCPH_FLAGS(tcphdr);
                if (checksum && tcphdr->chksum != 0)
                {
                    uint pseudo_checksum = CheckSum.inet_chksum_pseudo((byte*)p.ToPointer(),
                        (uint)ProtocolType.Tcp,
                        (uint)packet.Length,
                        ip.SourceAddressV4,
                        ip.DestinationAddressV4);
                    if (pseudo_checksum != 0)
                    {
                        return;
                    }
                }

                long payload_offset = 0;
                fixed (byte* stream = packet.Buffer)
                {
                    payload_offset = ((byte*)p + hdrlen_bytes) - stream;
                }

                BufferSegment message_data = new BufferSegment(packet.Buffer, unchecked((int)payload_offset), len);
                BufferSegment options_data = null;
                int options_size = hdrlen_bytes - sizeof(tcp_hdr);
                if (options_size <= 0)
                {
                    options_data = new BufferSegment(BufferSegment.Empty);
                }
                else
                {
                    options_data = new BufferSegment(packet.Buffer,
                            packet.Offset + sizeof(tcp_hdr), options_size);
                }
                frame = new TcpFrame(new IPEndPoint(ip.Source, CheckSum.ntohs(tcphdr->src)), new IPEndPoint(ip.Destination, CheckSum.ntohs(tcphdr->dest)), message_data)
                {
                    Ttl = ip.Ttl,
                    AcknowledgeNo = CheckSum.ntohl(tcphdr->ackno),
                    SequenceNo = CheckSum.ntohl(tcphdr->seqno),
                    WindowSize = CheckSum.ntohs(tcphdr->wnd),
                    Flags = flags,
                    SourceMacAddress = ip.SourceMacAddress,
                    DestinationMacAddress = ip.DestinationMacAddress,
                    Options = options_data,
                    UrgentPointer = CheckSum.ntohs(tcphdr->urgp)
                };
            });
            return frame;
        }

        public virtual TcpFrame Parse(IPFrame ip) => ParseFrame(ip);
    }
}
