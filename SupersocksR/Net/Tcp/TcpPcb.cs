namespace SupersocksR.Net.Tcp
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Net;
    using System.Net.Sockets;
    using SupersocksR.Core;
    using SupersocksR.Net;
    using SupersocksR.Net.Entry;

    public enum TcpState
    {
        CLOSED = 0,
        LISTEN = 1,
        SYN_SENT = 2,
        SYN_RCVD = 3,
        ESTABLISHED = 4,
        FIN_WAIT_1 = 5,
        FIN_WAIT_2 = 6,
        CLOSE_WAIT = 7,
        CLOSING = 8,
        LAST_ACK = 9,
        TIME_WAIT = 10
    }

    class TcpInputStream
    {
        public readonly LinkedList<TcpFrame> Frames = new LinkedList<TcpFrame>();
        public event EventHandler<TcpFrame> Receive;
        public readonly TcpPcb Pcb;

        public TcpInputStream(TcpPcb pcb)
        {
            this.Pcb = pcb ?? throw new ArgumentNullException(nameof(pcb));
        }

        public virtual void Input(TcpFrame frame)
        {
            if (frame == null || frame.Payload == null)
            {
                return;
            }

            if (frame.Payload.Length <= 0)
            {
                return;
            }

            lock (this.Frames)
            {
                if (frame.SequenceNo == this.Pcb.SequenceNo)
                {
                    this.Pcb.SequenceNo = frame.SequenceNo + (uint)frame.Payload.Length;
                    OnReceive(frame);

                    var node = this.Frames.First;
                    while (node != null)
                    {
                        TcpFrame f = node.Value;
                        var current = node;
                        node = current.Next;

                        if (f.SequenceNo == this.Pcb.SequenceNo)
                        {
                            this.Frames.Remove(current);
                            this.Pcb.SequenceNo = f.SequenceNo + (uint)f.Payload.Length;

                            OnReceive(f);
                        }
                    }
                }
                else if (this.Frames.Count <= 0)
                {
                    this.Frames.AddLast(frame);
                }
                else
                {
                    var node = this.Frames.Last;
                    if (frame.SequenceNo == node.Value.SequenceNo)
                    {
                        return;
                    }
                    else if (frame.SequenceNo > node.Value.SequenceNo)
                    {
                        this.Frames.AddLast(frame);
                    }
                    else
                    {
                        node = this.Frames.Last;
                        while (node != null)
                        {
                            TcpFrame f = node.Value;
                            if (f.SequenceNo == frame.SequenceNo)
                            {
                                return;
                            }
                            if (f.SequenceNo < frame.SequenceNo)
                            {
                                this.Frames.AddAfter(node, frame);
                                break;
                            }
                            node = node.Previous;
                        }
                        if (node == null)
                        {
                            this.Frames.AddFirst(frame);
                        }
                    }
                }
            }
        }

        protected virtual void OnReceive(TcpFrame frame)
        {
            this.Receive?.Invoke(this, frame);
        }
    }

    class TcpPcb : IPcb
    {
        public ILayerLocator Locator;
        public TcpState State;
        public uint SequenceNo;
        public uint AcknowledgeNo;
        public uint SendBufferSize;
        public uint ReceiveBufferSize;
        public IPEndPoint Source;
        public IPEndPoint Destination;
        public int Ttl;
        public bool Estableshed;
        public bool Aborted;

        public double RTT;
        public double SRTT;
        public double RTO;
        public double RTTVAL;

        public override EndPoint LocalEndPoint => this.Source;

        public override EndPoint RemoteEndPoint => this.Destination;

        public override AddressFamily AddressFamily { get; }

        public const int MIN_RTO = 200;

        public SortedDictionary<long, SegmentsContext> SegmentsContexts = new SortedDictionary<long, SegmentsContext>();
        public TcpInputStream InputStream;

        public TcpPcb(TcpFrame frame, ILayerLocator locator)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }

            this.Locator = locator ?? throw new ArgumentNullException(nameof(locator));
            this.AcknowledgeNo = frame.AcknowledgeNo;
            this.SequenceNo = frame.SequenceNo;
            this.AddressFamily = frame.AddressFamily;
            this.Destination = frame.Destination;
            this.Source = frame.Source;
            this.Ttl = frame.Ttl;
            this.Aborted = false;
            this.Estableshed = false;
            this.SendBufferSize = frame.WindowSize;
            this.ReceiveBufferSize = frame.WindowSize;
            this.InputStream = new TcpInputStream(this);
            this.InputStream.Receive += (sender, e) =>
            {
                uint ackNo = Convert.ToUInt32(e.SequenceNo + e.Payload.Length);
                uint seqNo = e.AcknowledgeNo;
                this.SequenceNo = ackNo;
                {
                    this.Post(TcpFlags.TCP_ACK, ackNo, seqNo, 0);
                }
                this.OnMessage(e.Payload);
            };
        }

        internal virtual void Post(TcpFlags flags, uint ackno, uint seqno, uint length = 0, int retransmission = 0, bool timeout = false)
        {
            SegmentsContext segments = null;
            lock (this)
            {
                lock (this.SegmentsContexts)
                {
                    segments = new SegmentsContext()
                    {
                        AcknowledgeNo = ackno,
                        SequenceNo = seqno,
                        Flags = flags,
                        Length = length,
                        Stopwatch = new Stopwatch(),
                        Retransmission = retransmission,
                        Pcb = this,
                        Timeout = timeout,
                    };
                    if (retransmission > 0)
                    {
                        long nackNo = segments.SequenceNo + segments.Length;
                        if (this.SegmentsContexts.TryAdd(nackNo, segments))
                        {
                            segments.Stopwatch.Start();
                        }
                    }
                }
            }
            TcpFrame frame = segments.CreateFrame(this);
            this.Locator.Tcp.Output(frame);
        }

        internal virtual bool Ack(long ackno)
        {
            bool ack = false;
            SegmentsContext segments = null;
            lock (this.SegmentsContexts)
            {
                ack = this.SegmentsContexts.Remove(ackno, out segments);
                if (ack)
                {
                    segments.Stopwatch.Stop();
                    UpdateAckTime(segments.Stopwatch.ElapsedMilliseconds);

                    if (this.State == TcpState.SYN_RCVD)
                    {
                        this.State = TcpState.ESTABLISHED;
                        this.OnOpen(EventArgs.Empty);
                    }
                }

                if (this.SegmentsContexts.Count > 0 && ackno <= this.AcknowledgeNo)
                {
                    var rapids = new List<long>();
                    foreach (var key in this.SegmentsContexts.Keys)
                    {
                        if (key > ackno)
                        {
                            break;
                        }

                        rapids.Add(key);
                    }
                    foreach (var key in rapids)
                    {
                        this.SegmentsContexts.Remove(key, out segments);
                    }
                }
            }
            return ack;
        }

        private void UpdateAckTime(long rtt)
        {
            RTT = Convert.ToInt64(rtt);
            if (0 == SRTT)
            {
                SRTT = RTT;
                RTTVAL = RTT / 2;
            }
            else
            {

                RTTVAL = ((RTTVAL * 3) + Math.Abs(RTT - SRTT)) / 4;
                SRTT = (7 * SRTT + RTT) / 8;
                SRTT = SRTT <= 0 ? 1 : SRTT;
            }
            RTO = SRTT + Math.Min(1, RTTVAL * 4);
            if (RTO < MIN_RTO)
            {
                RTO = MIN_RTO;
            }
        }

        public override string ToString()
        {
            return $"{this.Source} <-> {this.Destination}";
        }

        public override bool Send(BufferSegment payload)
        {
            if (payload == null || payload.Length <= 0)
            {
                return false;
            }

            bool sendto(BufferSegment buffer)
            {
                if (buffer == null || buffer.Length <= 0)
                {
                    return false;
                }

                SegmentsContext segments = null;
                lock (this)
                {
                    lock (this.SegmentsContexts)
                    {
                        segments = new SegmentsContext()
                        {
                            AcknowledgeNo = this.SequenceNo,
                            SequenceNo = this.AcknowledgeNo,
                            Flags = TcpFlags.TCP_PSH | TcpFlags.TCP_ACK,
                            Length = (uint)buffer.Length,
                            Stopwatch = new Stopwatch(),
                            Pcb = this,
                            Retransmission = 5,
                            Payload = payload,
                        };
                        var ackNo = segments.SequenceNo + segments.Length;
                        if (this.SegmentsContexts.TryAdd(ackNo, segments))
                        {
                            segments.Stopwatch.Start();
                            this.AcknowledgeNo += segments.Length;
                        }
                    }
                }

                TcpFrame frame = segments.CreateFrame(this);
                this.Locator.Tcp.Output(frame);

                return true;
            }

            foreach (BufferSegment buffer in Slices(payload))
            {
                if (!sendto(buffer))
                {
                    return false;
                }
            }
            return true;
        }

        private void CloseOrTimeout(bool timeout = false)
        {
            var pcb = this;
            lock (this)
            {
                if (!this.Aborted)
                {
                    uint seqno = pcb.AcknowledgeNo++;
                    uint ackno = pcb.SequenceNo;
                    if (timeout)
                    {
                        pcb.Post(TcpFlags.TCP_FIN | TcpFlags.TCP_ACK, ackno, seqno);
                    }
                    else
                    {
                        pcb.Post(TcpFlags.TCP_FIN | TcpFlags.TCP_ACK, ackno, seqno, 1, 3);
                    }
                    this.Aborted = false;
                    this.OnAbort(EventArgs.Empty);
                }
            }
        }

        public virtual void Timeout()
        {
            CloseOrTimeout(true);
        }

        public override void Close()
        {
            CloseOrTimeout();
        }
    }
}
