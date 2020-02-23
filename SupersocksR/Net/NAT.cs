namespace SupersocksR.Net
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Net;
    using System.Net.NetworkInformation;
    using System.Net.Sockets;
    using System.Threading;
    using SupersocksR.Net.Icmp;
    using SupersocksR.Net.IP;
    using SupersocksR.Net.Tcp;
    using SupersocksR.Net.Udp;
    using AddressFamily = System.Net.Sockets.AddressFamily;

    public class NATAgingTime // NAT老化时间
    {
        public int Dns = 60;         // 60s （H3C）
        public int Udp = 300;        // 300s
        public int Icmp = 60;        // 60s
        public int Tcp = 86400;      // 86400s
        public int Tcp_fin = 60;     // 60s FIN/RST
        public int Tcp_syn = 60;     // 60s
    }

    public unsafe class NAT
    {
        private readonly IPAddress m_ethernetAddress = IPAddress.Any;
        private readonly object m_syncobj = new object();
        private volatile int m_volatileNatConversionPort = new Random().Next(IPEndPoint.MinPort, IPEndPoint.MaxPort);
        private readonly NATContextPortTable m_contextsUdp = null;
        private readonly NATContextPortTable m_contextsTcp = null;
        private readonly NATContextIcmpTable m_contextsIcmp = null;
        private readonly NATAgingTime m_natAgingTime = new NATAgingTime();

        public event EventHandler<IPFrame> PublicOutput;
        public event EventHandler<IPFrame> PrivateOutput;

        private class NATContextPortTable
        {
            private readonly ConcurrentDictionary<long, NATContext> m_AddressToContext = new ConcurrentDictionary<long, NATContext>();
            private readonly ConcurrentDictionary<long, NATContext> m_SourcesToContext = new ConcurrentDictionary<long, NATContext>();
            private readonly NAT m_nat = null;
            private readonly object m_syncobj = new object();
            private readonly Stopwatch m_tickAlaywsPeriod = new Stopwatch();

            public ProtocolType ProtocolType { get; }

            public NATContextPortTable(NAT nat, ProtocolType protocolType)
            {
                this.m_nat = nat ?? throw new ArgumentNullException(nameof(nat));
                this.ProtocolType = protocolType;
                this.DoEvents();
            }

            public virtual void DoEvents()
            {
                lock (this.m_AddressToContext)
                {
                    lock (this.m_syncobj)
                    {
                        if (!this.m_tickAlaywsPeriod.IsRunning || this.m_tickAlaywsPeriod.ElapsedMilliseconds >= 1000)
                        {
                            foreach (NATContext context in this.m_AddressToContext.Values)
                            {
                                if (context == null)
                                    continue;
                                int seconds = 0;
                                if (this.ProtocolType == ProtocolType.Udp)
                                {
                                    seconds = this.m_nat.m_natAgingTime.Udp;
                                    if (context.Destination.Port == 53)
                                        seconds = this.m_nat.m_natAgingTime.Dns;
                                }
                                else if (this.ProtocolType == ProtocolType.Tcp)
                                {
                                    seconds = 0;
                                    switch (context.State)
                                    {
                                        case NATContext.StateCode.TCP_FIN:
                                            seconds = this.m_nat.m_natAgingTime.Tcp_fin;
                                            break;
                                        case NATContext.StateCode.TCP_RST:
                                            seconds = this.m_nat.m_natAgingTime.Tcp_fin;
                                            break;
                                        case NATContext.StateCode.TCP_RECVED:
                                            seconds = this.m_nat.m_natAgingTime.Tcp;
                                            break;
                                        case NATContext.StateCode.TCP_SYN:
                                            seconds = this.m_nat.m_natAgingTime.Tcp_syn;
                                            break;
                                    };
                                }
                                if (!context.IsAgingTime(seconds))
                                    continue;
                                this.m_AddressToContext.TryRemove(context.LocalEP.Port, out NATContext context_x);
                                this.m_SourcesToContext.TryRemove(EndPointToLongKey(context.Sources), out NATContext context_xx);
                                context.Dispose();
                            }
                            this.m_tickAlaywsPeriod.Restart();
                        }
                    }
                }
            }

            public virtual int Release(IPAddress sources)
            {
                int events = 0;
                if (sources == null)
                {
                    return events;
                }
                lock (this.m_AddressToContext)
                {
                    lock (this.m_syncobj)
                    {
                        IList<NATContext> s = new List<NATContext>();
                        foreach (NATContext context in this.m_AddressToContext.Values)
                        {
                            if (context == null)
                                continue;
                            if (Equals(context.Sources.Address, sources))
                                s.Add(context);
                        }
                        foreach (NATContext context in s)
                        {
                            events++;
                            this.m_AddressToContext.TryRemove(context.LocalEP.Port, out NATContext context_x);
                            this.m_SourcesToContext.TryRemove(EndPointToLongKey(context.Sources), out NATContext context_xx);
                            context.Dispose();
                        }
                    }
                }
                return events;
            }

            private NATContext RestartContextAgingTime(NATContext context)
            {
                if (context == null)
                {
                    return context;
                }
                if (this.ProtocolType != ProtocolType.Tcp)
                {
                    return context;
                }
                if (context.State == NATContext.StateCode.TCP_RECVED || context.State == NATContext.StateCode.TCP_SYN)
                {
                    return context.Restart();
                }
                return context;
            }

            protected virtual int NewBindPort(ProtocolType protocolType)
            {
                for (int i = 0; i < 100; i++)
                {
                    int port = this.m_nat.NewAnyProtocolVirtualPort();
                    if (protocolType == ProtocolType.Tcp)
                    {
                        var properties = IPGlobalProperties.GetIPGlobalProperties();
                        if (properties.GetActiveTcpListeners().FirstOrDefault(ep => ep.Port == port) != null)
                        {
                            continue;
                        }
                        if (properties.GetActiveTcpConnections().FirstOrDefault(tci => tci.LocalEndPoint.Port == port) != null)
                        {
                            continue;
                        }
                    }
                    else if (protocolType == ProtocolType.Udp)
                    {
                        if (protocolType == ProtocolType.Udp)
                        {
                            if (IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().
                                FirstOrDefault(ep => ep.Port == port) != null)
                            {
                                continue;
                            }
                        }
                    }
                    if (this.m_AddressToContext.ContainsKey(port))
                    {
                        continue;
                    }
                    return port;
                }
                return 0;
            }

            public virtual NATContext PrivateInput(IPEndPoint sources, IPEndPoint destination, bool creational, bool autorestat = true)
            {
                if (sources == null || destination == null)
                {
                    return null;
                }
                else
                {
                    this.DoEvents();
                }
                long keySourcesContext = EndPointToLongKey(sources);
                lock (this.m_AddressToContext)
                {
                    lock (this.m_syncobj)
                    {
                        this.m_SourcesToContext.TryGetValue(keySourcesContext, out NATContext context);
                        if (context == null)
                        {
                            if (!creational)
                            {
                                return null;
                            }
                            if (this.m_AddressToContext.Count >= IPEndPoint.MaxPort)
                            {
                                return null;
                            }
                            int port = NewBindPort(this.ProtocolType);
                            if (port > IPEndPoint.MinPort && port <= IPEndPoint.MaxPort)
                            {
                                IPEndPoint localEP = new IPEndPoint(this.m_nat.m_ethernetAddress, port);
                                if (localEP != null)
                                {
                                    context = new NATContext()
                                    {
                                        Sources = sources,
                                        Destination = destination,
                                        LocalEP = localEP,
                                        AgingTimePeriod = new Stopwatch(),
                                        State = NATContext.StateCode.TCP_NIL,
                                    };
                                    this.m_AddressToContext[localEP.Port] = context;
                                    this.m_SourcesToContext[keySourcesContext] = context;
                                }
                            }
                        }
                        if (!autorestat)
                        {
                            return context;
                        }
                        return RestartContextAgingTime(context);
                    }
                }
            }

            public virtual NATContext PublicInput(IPEndPoint sources, IPEndPoint destination)
            {
                if (sources == null || destination == null)
                {
                    return null;
                }
                if (!Equals(destination.Address, this.m_nat.m_ethernetAddress))
                {
                    return null;
                }
                this.DoEvents();
                lock (this.m_AddressToContext)
                {
                    lock (this.m_syncobj)
                    {
                        this.m_AddressToContext.TryGetValue(destination.Port, out NATContext context);
                        return RestartContextAgingTime(context);
                    }
                }
            }
        }

        private class NATContextIcmpTable
        {
            private readonly ConcurrentDictionary<long, NATContext> m_AddressToContext = new ConcurrentDictionary<long, NATContext>();
            private readonly NAT m_nat = null;
            private readonly object m_syncobj = new object();
            private readonly Stopwatch m_tickAlaywsPeriod = new Stopwatch();

            public ProtocolType ProtocolType { get; }

            public NATContextIcmpTable(NAT nat, ProtocolType protocolType)
            {
                this.m_nat = nat ?? throw new ArgumentNullException(nameof(nat));
                this.ProtocolType = protocolType;
                this.DoEvents();
            }

            public virtual IEnumerable<NATContext> GetAllContext()
            {
                return this.m_AddressToContext.Values;
            }

            public virtual void DoEvents()
            {
                lock (this.m_AddressToContext)
                {
                    lock (this.m_syncobj)
                    {
                        if (!this.m_tickAlaywsPeriod.IsRunning || this.m_tickAlaywsPeriod.ElapsedMilliseconds >= 1000)
                        {
                            foreach (NATContext context in this.m_AddressToContext.Values)
                            {
                                if (context == null)
                                    continue;
                                int seconds = 0;
                                if (this.ProtocolType == ProtocolType.Icmp)
                                    seconds = this.m_nat.m_natAgingTime.Icmp;
                                if (!context.IsAgingTime(seconds))
                                    continue;
                                Release(context.Sources.Address);
                            }
                        }
                    }
                }
            }

            public virtual int Release(IPAddress sources)
            {
                long sources_key = Ethernet.GetAddress(sources);
                if (sources == null)
                {
                    return 0;
                }
                NATContext context = null;
                lock (this.m_AddressToContext)
                {
                    lock (this.m_syncobj)
                    {
                        this.m_AddressToContext.TryRemove(sources_key, out context);
                        if (context == null)
                        {
                            return 0;
                        }
                    }
                }
                context.Dispose();
                return 1;
            }

            public virtual NATContext PrivateInput(IPAddress sources, IPAddress destination, ushort Identification)
            {
                if (sources == null || destination == null)
                {
                    return null;
                }
                this.DoEvents();
                long sources_key = Ethernet.GetAddress(sources);
                lock (this.m_AddressToContext)
                {
                    lock (this.m_syncobj)
                    {
                        this.m_AddressToContext.TryGetValue(sources_key, out NATContext context);
                        if (context == null && 0 != Identification)
                        {
                            context = new NATContext()
                            {
                                LocalEP = new IPEndPoint(this.m_nat.m_ethernetAddress, 0),
                                AgingTimePeriod = new Stopwatch(),
                                Sources = new IPEndPoint(sources, Identification),
                                Destination = new IPEndPoint(destination, 0),
                                State = NATContext.StateCode.TCP_NIL,
                            };
                            this.m_AddressToContext[sources_key] = context;
                        }
                        return context?.Restart();
                    }
                }
            }
        }

        private class NATContext : IDisposable
        {
            public enum StateCode
            {
                TCP_NIL,
                TCP_SYN,
                TCP_FIN,
                TCP_RST,
                TCP_RECVED,
            }

            public IPEndPoint LocalEP;          // NAT分配地址点
            public Stopwatch AgingTimePeriod;   // 老化周期
            public IPEndPoint Sources;          // 源来地址
            public IPEndPoint Destination;      // 目标地址
            public StateCode State;

            ~NATContext()
            {
                this.Dispose();
            }

            public NATContext Restart()
            {
                this.AgingTimePeriod?.Restart();
                return this;
            }

            public bool IsAgingTime(int max)
            {
                if (max <= 0)
                {
                    return true;
                }

                Stopwatch sw = this.AgingTimePeriod;
                if (sw == null)
                {
                    return true;
                }

                double seconds = sw.ElapsedMilliseconds;
                if (seconds <= 0)
                {
                    seconds = 0;
                }
                else
                {
                    seconds /= 1000;
                }

                return seconds >= max;
            }

            public virtual void Dispose()
            {
                GC.SuppressFinalize(this);
            }
        }

        public virtual int Release(IPAddress address)
        {
            int events = 0;
            if (address == null)
            {
                return events;
            }
            events += this.m_contextsIcmp.Release(address);
            events += this.m_contextsTcp.Release(address);
            events += this.m_contextsUdp.Release(address);
            return events;
        }
        
        public NAT(IPAddress ethernet)
        {
            this.m_ethernetAddress = ethernet ?? IPAddress.Any;
            this.m_contextsUdp = new NATContextPortTable(this, ProtocolType.Udp);
            this.m_contextsTcp = new NATContextPortTable(this, ProtocolType.Tcp);
            this.m_contextsIcmp = new NATContextIcmpTable(this, ProtocolType.Icmp);
        }

        public IPAddress GetEthernetAddress() => this.m_ethernetAddress;

        public NATAgingTime GetAgingTime() => this.m_natAgingTime;

        protected int NewAnyProtocolVirtualPort()
        {
            int port = 0;
            do
            {
                port = Interlocked.Increment(ref this.m_volatileNatConversionPort);
                if (port <= IPEndPoint.MinPort || port >= IPEndPoint.MaxPort)
                {
                    Interlocked.Exchange(ref this.m_volatileNatConversionPort, IPEndPoint.MinPort);
                }
                else
                {
                    break;
                }
            } while (true);
            return port;
        }

        private void TraceTcpNatContext(NATContext context, TcpFrame frame)
        {
            if (context == null || frame == null)
            {
                return;
            }
            NATContext.StateCode state = NATContext.StateCode.TCP_RST; // 跟踪TCP协议报文状态
            if (0 != (frame.Flags & TcpFlags.TCP_SYN))
            {
                state = NATContext.StateCode.TCP_SYN;
            }
            else if (0 != (frame.Flags & TcpFlags.TCP_FIN))
            {
                state = NATContext.StateCode.TCP_FIN;
            }
            else if (0 != (frame.Flags & TcpFlags.TCP_RST))
            {
                state = NATContext.StateCode.TCP_RST;
            }
            else if (0 != (frame.Flags & (TcpFlags.TCP_PSH | TcpFlags.TCP_ACK)))
            {
                state = NATContext.StateCode.TCP_RECVED;
            }
            if (context.State != NATContext.StateCode.TCP_FIN &&
                context.State != NATContext.StateCode.TCP_RST)
            {
                context.Restart().State = state;
            }
        }

        public virtual bool PrivateInput(IPFrame packet)
        {
            if (packet == null)
            {
                return false;
            }
            switch (packet.ProtocolType)
            {
                case ProtocolType.Udp:
                    {
                        UdpFrame frame = UdpLayer.ParseFrame(packet, false);
                        if (frame == null)
                        {
                            return false;
                        }
                        NATContext context = this.m_contextsUdp.PrivateInput(frame.Source, frame.Destination, true);
                        if (context == null)
                        {
                            return false;
                        }
                        var convertional = new UdpFrame(context.LocalEP, context.Destination, frame.Payload)
                        {
                            Ttl = frame.Ttl,
                        };
                        IPFrame ip = CopyFrameHeaderParts(UdpLayer.ToIPFrame(convertional), packet);
                        if (ip == null)
                        {
                            return false;
                        }
                        return this.OnPublicOutput(ip);
                    }
                case ProtocolType.Tcp:
                    {
                        TcpFrame frame = TcpLayer.ParseFrame(packet, false);
                        if (frame == null)
                        {
                            return false;
                        }
                        NATContext context = this.m_contextsTcp.PrivateInput(frame.Source, 
                            frame.Destination, 0 != (frame.Flags & TcpFlags.TCP_SYN), false);
                        if (context == null)
                        {
                            return false;
                        }
                        else
                        {
                            TraceTcpNatContext(context, frame);
                        }
                        var convertional = new TcpFrame(context.LocalEP, context.Destination, frame.Payload)
                        {
                            Ttl = frame.Ttl,
                            AcknowledgeNo = frame.AcknowledgeNo,
                            Flags = frame.Flags,
                            SequenceNo = frame.SequenceNo,
                            WindowSize = frame.WindowSize,
                            Options = frame.Options,
                            UrgentPointer = frame.UrgentPointer,
                        };
                        IPFrame ip = CopyFrameHeaderParts(TcpLayer.ToIPFrame(convertional), packet);
                        if (ip == null)
                        {
                            return false;
                        }
                        return this.OnPublicOutput(ip);
                    }
                case ProtocolType.Icmp:
                    return this.PrivateIcmpInput(packet);
                default:
                    return false;
            }
        }

        public virtual bool PublicInput(IPFrame packet)
        {
            if (packet == null)
            {
                return false;
            }
            switch (packet.ProtocolType)
            {
                case ProtocolType.Udp:
                    {
                        UdpFrame frame = UdpLayer.ParseFrame(packet, true);
                        if (frame == null)
                        {
                            return false;
                        }
                        NATContext context = this.m_contextsUdp.PublicInput(frame.Source, frame.Destination);
                        if (context == null)
                        {
                            return false;
                        }
                        var convertional = new UdpFrame(frame.Source, context.Sources, frame.Payload)
                        {
                            Ttl = frame.Ttl,
                        };
                        IPFrame ip = CopyFrameHeaderParts(UdpLayer.ToIPFrame(convertional), packet);
                        if (ip == null)
                        {
                            return false;
                        }
                        return this.OnPrivateOutput(ip);
                    }
                case ProtocolType.Tcp:
                    {
                        TcpFrame frame = TcpLayer.ParseFrame(packet, true);
                        if (frame == null)
                        {
                            return false;
                        }
                        NATContext context = this.m_contextsTcp.PublicInput(frame.Source, frame.Destination);
                        if (context == null)
                        {
                            return false;
                        }
                        else
                        {
                            TraceTcpNatContext(context, frame);
                        }
                        var convertional = new TcpFrame(frame.Source, context.Sources, frame.Payload)
                        {
                            Ttl = frame.Ttl,
                            AcknowledgeNo = frame.AcknowledgeNo,
                            Flags = frame.Flags,
                            SequenceNo = frame.SequenceNo,
                            WindowSize = frame.WindowSize,
                            Options = frame.Options,
                            UrgentPointer = frame.UrgentPointer,
                        };
                        IPFrame ip = CopyFrameHeaderParts(TcpLayer.ToIPFrame(convertional), packet);
                        if (ip == null)
                        {
                            return false;
                        }
                        return this.OnPrivateOutput(ip);
                    }
                case ProtocolType.Icmp:
                    return this.PublicIcmpInput(packet);
                default:
                    return false;
            }
        }

        private bool PrivateIcmpInput(IPFrame packet)
        {
            IcmpFrame frame = IcmpLayer.ParseFrame(packet, false);
            if (frame == null)
            {
                return false;
            }
            NATContext context = this.m_contextsIcmp.PrivateInput(frame.Source, frame.Destination, frame.Identification);
            if (context == null)
            {
                return false;
            }
            IcmpFrame convertional = null;
            int ttl = frame.Ttl - 1;
            if (ttl <= 0)
            {
                convertional = new IcmpFrame(this.m_ethernetAddress, frame.Source, IPv4Layer.ToArray(packet))
                {
                    Ttl = packet.Ttl,
                    Type = IcmpType.ICMP_TE,
                    Code = 0,
                    Sequence = 0,
                    Identification = 0,
                };
                IPFrame replay = CopyFrameHeaderParts(IcmpLayer.ToIPFrame(convertional), packet);
                if (replay == null)
                {
                    return false;
                }
                return this.OnPrivateOutput(replay);
            }
            else
            {
                convertional = new IcmpFrame(this.m_ethernetAddress, frame.Destination, frame.Payload)
                {
                    Ttl = ttl,
                    Type = frame.Type,
                    Code = frame.Code,
                    Sequence = frame.Sequence,
                    Identification = frame.Identification/*unchecked((ushort)context.Destination.Port)*/,
                };
            }
            IPFrame ip = CopyFrameHeaderParts(IcmpLayer.ToIPFrame(convertional), packet);
            if (ip == null)
            {
                return false;
            }
            return this.OnPublicOutput(ip);
        }

        protected virtual bool PublicIcmpInput(IPFrame packet)
        {
            IcmpFrame frame = IcmpLayer.ParseFrame(packet, true); // NDIS5/6内核层已检查过所以无需要重复计算ICMP报文CHECKSUM
            if (frame == null)
            {
                return false;
            }
            bool success = false; // 不知道这样的数据报文应该发向那个主机时广播到还允许NAT穿透ICMP报文的多个主机（但仅限对于ICMP/NAT）
            foreach (NATContext secondary in this.m_contextsIcmp.GetAllContext()) // 稳定可靠NAT不丢帧（但可能造成虚拟NAT层压力过载）
            {
                success |= this.PublicIcmpNATOutput(secondary, frame, packet);
            }
            return success;
        }

        private bool PublicIcmpNATOutput(NATContext context, IcmpFrame frame, IPFrame packet)
        {
            if (context == null || frame == null || packet == null)
            {
                return false;
            }
            if (frame.Type != IcmpType.ICMP_ER) // TIME EXCEEDED
            {
                IPFrame ipAgo = IPv4Layer.ParseFrame(frame.Payload, false);
                IcmpFrame icmpAgo = IcmpLayer.ParseFrame(ipAgo, false);
                if (icmpAgo == null) // 这是一个伪造的ICMP数据报，正确报文应答必须要包含从本机发向对端主机的ICMP/IP数据报文
                {
                    return false;
                }
                ipAgo = CopyFrameHeaderParts(IcmpLayer.ToIPFrame(new IcmpFrame(frame.Source, context.Sources.Address, icmpAgo.Payload)  // 重新汇编整个ICMP/IP数据报文
                {
                    Ttl = icmpAgo.Ttl,
                    Type = icmpAgo.Type,
                    Code = icmpAgo.Code,
                    Sequence = icmpAgo.Sequence,
                    Identification = unchecked((ushort)context.Sources.Port), // 客户端ICMP协议请求时的凭证编号
                }), ipAgo);
                frame.Payload = IPv4Layer.ToArray(ipAgo);
            }
            var convertional = new IcmpFrame(frame.Source, context.Sources.Address, frame.Payload)
            {
                Ttl = frame.Ttl - 1,
                Type = frame.Type,
                Code = frame.Code,
                Sequence = frame.Sequence,
                Identification = frame.Identification,
            };
            IPFrame ip = CopyFrameHeaderParts(IcmpLayer.ToIPFrame(convertional), packet);
            if (ip == null)
            {
                return false;
            }
            return this.OnPrivateOutput(ip);
        }

        private static IPFrame CopyFrameHeaderParts(IPFrame ip, IPFrame packet)
        {
            if (ip != null && packet != null)
            {
                ip.Id = packet.Id;
                ip.Tos = packet.Tos;
                ip.Options = packet.Options;
                ip.Flags = packet.Flags;
                ip.SourceMacAddress = packet.SourceMacAddress;
                ip.DestinationMacAddress = packet.DestinationMacAddress;
            }
            return ip;
        }

        protected virtual bool OnPublicOutput(IPFrame frame)
        {
            if (frame == null)
            {
                return false;
            }

            this.PublicOutput?.Invoke(this, frame);
            return true;
        }

        protected virtual bool OnPrivateOutput(IPFrame frame)
        {
            if (frame == null)
            {
                return false;
            }

            this.PrivateOutput?.Invoke(this, frame);
            return true;
        }

        public static long EndPointToLongKey(EndPoint localEP)
        {
            if (localEP is IPEndPoint ep)
            {
                if (ep.AddressFamily == AddressFamily.InterNetwork)
                {
                    fixed (byte* pinned = ep.Address.GetAddressBytes())
                    {
                        long address = *(uint*)pinned;
                        long key = address << 32 | (long)ep.Port;
                        return key;
                    }
                }
            }
            return 0;
        }

        public static IPEndPoint LongKeyToEndPoint(long key)
        {
            uint address = unchecked((uint)(key >> 32));
            int port = unchecked((int)key);
            return new IPEndPoint(new IPAddress(address), port);
        }
    }
}
