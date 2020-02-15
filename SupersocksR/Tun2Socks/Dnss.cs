namespace SupersocksR.Tun2Socks
{
    using System;
    using System.Collections;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;
    using SupersocksR.Core;
    using SupersocksR.Net.Dns.OpenDNS;
    using SupersocksR.Net.Tun;

    public unsafe class Dnss : IDisposable
    {
        private readonly object m_syncobj = new object();
        private volatile bool m_disposed = false;
        private readonly Socket m_poSocket = null;
        private readonly byte[] m_szBuffer = new byte[Layer3Netif.MTU];
        private readonly IPEndPoint[] m_dnsServer = new[] 
        {
            new IPEndPoint(IPAddress.Parse("8.8.8.8"), Dnss.Port),
            new IPEndPoint(IPAddress.Parse("8.8.4.4"), Dnss.Port)
        };
        private Thread m_poListenThread = null;
        private TUN2Socks m_poTUN2Socks = null;
        private volatile int m_iVfptrAddress = 0;
        private ConcurrentDictionary<string, IPAddress> m_poDnsMap = new ConcurrentDictionary<string, IPAddress>();
        private ConcurrentDictionary<IPAddress, string> m_poDnsMapFar = new ConcurrentDictionary<IPAddress, string>();

        public const int Port = 53;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct DNSHeader
        {
            public ushort usTransID;         // 标识符
            public ushort usFlags;           // 各种标志位
            public ushort usQuestionCount;   // Question字段个数 
            public ushort usAnswerCount;     // Answer字段个数
            public ushort usAuthorityCount;  // Authority字段个数
            public ushort usAdditionalCount; // Additional字段个数
        }

        public Dnss(TUN2Socks tun2socks) : this(tun2socks, Dnss.Port)
        {

        }

        public Dnss(TUN2Socks tun2socks, int port)
        {
            this.m_iVfptrAddress = BitConverter.ToInt32(IPAddress.Parse("198.18.0.0").GetAddressBytes(), 0);
            this.m_iVfptrAddress = IPAddress.NetworkToHostOrder(this.m_iVfptrAddress);

            this.m_poTUN2Socks = tun2socks ?? throw new ArgumentNullException(nameof(tun2socks));
            this.m_poSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            this.m_poSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            this.m_poSocket.Bind(new IPEndPoint(IPAddress.Any, port));
        }

        protected virtual IPAddress NewVirtualAddress()
        {
            int address_number = 0;
            while (true)
            {
                address_number = Interlocked.Increment(ref this.m_iVfptrAddress);

                int by4 = address_number & 0xff;
                if (0 == by4)
                {
                    continue;
                }

                if (0xff == by4)
                {
                    continue;
                }

                break;
            }
            return new IPAddress(CheckSum.ntohl((uint)address_number));
        }

        ~Dnss()
        {
            this.Dispose();
        }

        public class DnsRequest
        {
            public string Domain { get; internal set; }

            public int QueryID { get; internal set; }

            public Types QueryType { get; internal set; }

            public Classes QueryClass { get; internal set; }

            public BufferSegment Message { get; internal set; }
        }

        public class DnsResponse : IEnumerable<ResourceRecord>
        {
            public int QueryID { get; internal set; }

            // AA
            public bool AuthorativeAnswer { get; internal set; }

            // TC
            public bool IsTruncated { get; internal set; }

            // RD
            public bool RecursionRequested { get; internal set; }

            // RA
            public bool RecursionAvailable { get; internal set; }

            // RC
            public ResponseCodes ResponseCode { get; internal set; }

            public ResourceRecordCollection Questions { get; internal set; } = new ResourceRecordCollection();

            public ResourceRecordCollection Answers { get; internal set; } = new ResourceRecordCollection();

            public ResourceRecordCollection Authorities { get; internal set; } = new ResourceRecordCollection();

            public ResourceRecordCollection AdditionalRecords { get; internal set; } = new ResourceRecordCollection();

            public virtual IEnumerator<ResourceRecord> GetEnumerator()
            {
                foreach (ResourceRecord rr in this.Answers)
                    yield return rr;

                foreach (ResourceRecord rr in this.Authorities)
                    yield return rr;

                foreach (ResourceRecord rr in this.AdditionalRecords)
                    yield return rr;
            }

            private void WriteResourceRecord(BinaryWriter message_writer, ResourceRecordCollection resources)
            {
                foreach (ResourceRecord rr in resources)
                {
                    WriteResourceString(message_writer, rr.Name);

                    message_writer.Write(CheckSum.ntohs((ushort)rr.Type));
                    message_writer.Write(CheckSum.ntohs((ushort)rr.Class));
                    message_writer.Write(CheckSum.ntohl((uint)rr.TimeToLive));

                    // RDLength (Get Resource Data Length)
                    switch (rr.Type)
                    {
                        case Types.A:
                            {
                                Address rrA = (Address)rr;
                                message_writer.Write(CheckSum.ntohs(4));
                                message_writer.Write(rrA.IP.GetAddressBytes());
                            }
                            break;
                        case Types.AAAA:
                            {
                                Address rrA = (Address)rr;
                                message_writer.Write(CheckSum.ntohs(16));
                                message_writer.Write(rrA.IP.GetAddressBytes());
                            }
                            break;
                        case Types.CNAME:
                            {
                                WriteResourceString(message_writer, rr.RText, true);
                            }
                            break;
                    };
                }
            }

            private void WriteResourceString(BinaryWriter message_writer, string encoding_str, bool write_pre_length = false)
            {
                if (write_pre_length)
                {
                    ushort pre_length = 1;
                    foreach (string pLabel in encoding_str.Split('.'))
                    {
                        byte[] encoding_bytes = Encoding.UTF8.GetBytes(pLabel);
                        byte max_encoding_bytes = (byte)Math.Min(encoding_bytes.Length, 0xc0);
                        pre_length += (ushort)(max_encoding_bytes + 1);
                    }
                    message_writer.Write(CheckSum.ntohs(pre_length));
                    WriteResourceString(message_writer, encoding_str);
                }
                else
                {
                    foreach (string pLabel in encoding_str.Split('.'))
                    {
                        byte[] encoding_bytes = Encoding.UTF8.GetBytes(pLabel);
                        byte max_encoding_bytes = (byte)Math.Min(encoding_bytes.Length, 0xc0);
                        message_writer.Write(max_encoding_bytes);
                        message_writer.Write(encoding_bytes, 0, max_encoding_bytes);
                    }
                    message_writer.Write((byte)'\x00');
                }
            }

            public virtual BufferSegment ToArray()
            {
                unchecked
                {
                    MemoryStream message = new MemoryStream();
                    BinaryWriter message_writer = new BinaryWriter(message);
                    message_writer.Write(CheckSum.ntohs((ushort)this.QueryID));

                    int flags = 1 << 1; // QR
                    flags <<= 4; // OP
                    flags |= this.AuthorativeAnswer ? 1 : 0;
                    flags <<= 1; // AA
                    flags |= this.IsTruncated ? 1 : 0;
                    flags <<= 1; // TC
                    flags |= this.RecursionRequested ? 1 : 0;
                    flags <<= 1; // RD
                    flags |= this.RecursionAvailable ? 1 : 0;
                    flags <<= 3 + 4; // Z(1~3)
                    flags |= (int)this.ResponseCode; // RC

                    message_writer.Write(CheckSum.ntohs((ushort)flags));
                    message_writer.Write(CheckSum.ntohs((ushort)this.Questions.Count));
                    message_writer.Write(CheckSum.ntohs((ushort)this.Answers.Count));
                    message_writer.Write(CheckSum.ntohs((ushort)this.Authorities.Count));
                    message_writer.Write(CheckSum.ntohs((ushort)this.AdditionalRecords.Count));

                    foreach (ResourceRecord rr in this.Questions)
                    {
                        WriteResourceString(message_writer, rr.Name);
                        message_writer.Write(CheckSum.ntohs((ushort)rr.Type));
                        message_writer.Write(CheckSum.ntohs((ushort)rr.Class));
                    }

                    WriteResourceRecord(message_writer, this.Answers);
                    WriteResourceRecord(message_writer, this.Authorities);
                    WriteResourceRecord(message_writer, this.AdditionalRecords);

                    return new BufferSegment(message.GetBuffer(), 0, Convert.ToInt32(message.Position));
                }
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return this.GetEnumerator();
            }

            public static DnsResponse From(byte[] buffer) => From(buffer, buffer?.Length ?? 0);

            public static DnsResponse From(byte[] buffer, int length)
            {
                if (buffer == null || length <= 0)
                {
                    return null;
                }

                DnsQuery query = new DnsQuery(string.Empty, Types.A);
                query.data = buffer;
                query.length = length;
                query.ReadResponse();

                return new DnsResponse
                {
                    AdditionalRecords = query.Response.AdditionalRecords,
                    Answers = query.Response.Answers,
                    AuthorativeAnswer = query.Response.AuthorativeAnswer,
                    Authorities = query.Response.Authorities,
                    IsTruncated = query.Response.IsTruncated,
                    QueryID = query.Response.QueryID,
                    ResponseCode = query.Response.ResponseCode,
                    RecursionRequested = query.Response.RecursionRequested,
                    RecursionAvailable = query.Response.RecursionAvailable,
                    Questions = query.Response.Questions
                };
            }

            public static IEnumerable<IPAddress> GetAddresses(ResourceRecordCollection s)
            {
                ISet<IPAddress> r = new HashSet<IPAddress>();
                if (s == null)
                {
                    return r;
                }
                foreach (ResourceRecord rr in s)
                {
                    if (rr.Type == Types.A || rr.Type == Types.AAAA)
                    {
                        Address rrA = (Address)rr;
                        r.Add(rrA.IP);
                    }
                }
                return r;
            }

            public static IEnumerable<string> FetchAddresses(ResourceRecordCollection s)
            {
                ISet<string> r = new HashSet<string>();
                if (s == null)
                {
                    return r;
                }
                foreach (ResourceRecord rr in s)
                {
                    if (rr.Type == Types.A || rr.Type == Types.AAAA)
                    {
                        Address rrA = (Address)rr;
                        r.Add(rrA.IP.ToString());
                    }
                    else if (rr.Type == Types.CNAME)
                    {
                        r.Add(rr.RText);
                    }
                }
                return r;
            }
        }

        private bool ProcessRequest(byte[] buffer, int offset, int length, EndPoint remoteEP)
        {
            fixed (byte* pinned = &buffer[offset])
            {
                // 设当前收取到的UDP帧长度不足DNS协议头的长度则返回假。
                if (length < sizeof(DNSHeader))
                {
                    return false;
                }

                // 转换当前请求的二进制数据的指针为DNS协议头部指针。
                DNSHeader* request = (DNSHeader*)pinned;

                // 不支持除A4地址解析以外的任何DNS协议（不过按照INETv4以太网卡也不可能出现A6地址析请求）
                // A6根本不需要虚拟网卡链路层网络远程桥接，先天的scope机制就足以抵御外部入侵的防火长城。
                if (0 == (CheckSum.ntohs(request->usFlags) & 0x0100))
                {
                    return false;
                }

                // 若客户端查询问题是空直接不给客户端应答就让它卡在那里用户态（RING3）通过系统DNS服务进行解析不太可能是请求空答案。
                // 虽然这会造成系统内核使用处于等待数据包应答的状态；句柄资源无法释放但是已经不太重要了；底层也不太好操作把上层
                // 搞崩溃，搞太猛系统就蓝屏了；当然倒是可以强制把目标进程的内存全部设置为WPOFF让它死的难看至极。
                // 不过这么搞了就必须要在RING0做防护了；万一逗逼跑来强制从内核卸载怎么办，一定要让这些人付出代价必须蓝屏死机。
                // 虽然这并不是没有办法。对付小小的用户态程式方法真的太多，搞死它只要你想轻而易举；毕竟应用层都是最低贱的程式。
                if (0 == CheckSum.htons(request->usQuestionCount))
                {
                    return false;
                }

                // 应答客户端查询DNS的请求，DNS地址污染并且强制劫持到分配的保留地址段假IP。
                byte* pszPayload = (byte*)(request + 1);

                // 从DNS协议流中获取需要解析的域名。
                string szHostname = string.Empty;
                while ('\x0' != *pszPayload)
                {
                    byte len = *pszPayload++;
                    if (szHostname.Length > 0)
                    {
                        szHostname += ".";
                    }
                    szHostname += new string((sbyte*)pszPayload, 0, len);
                    pszPayload += len;
                }

                // 查询字符串的最后一个字节是\x0中止符号。
                pszPayload++;

                // 问题所需求的查询类型。
                ushort usQType = CheckSum.ntohs(*(ushort*)pszPayload);
                pszPayload += sizeof(ushort);

                // 问题所需求的查询类别。
                ushort usQClass = CheckSum.ntohs(*(ushort*)pszPayload);
                pszPayload += sizeof(ushort);

                // 处理来自己客户端的DNS请求。
                return this.OnRequest(new DnsRequest
                {
                    Domain = szHostname,
                    QueryClass = (Classes)usQClass,
                    QueryType = (Types)usQType,
                    QueryID = CheckSum.htons(request->usTransID),
                    Message = new BufferSegment(new BufferSegment(buffer, offset, length).ToArray())
                }, remoteEP);
            }
        }

        protected virtual bool SuperiorAcquired(DnsRequest request, Action<BufferSegment, DnsResponse> answer)
        {
            Socket dns = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                dns.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1500);
                foreach (IPEndPoint dnsServer in this.m_dnsServer)
                {
                    dns.SendTo(request.Message.Buffer,
                        request.Message.Offset,
                        request.Message.Length, SocketFlags.None, dnsServer);
                }
                byte[] response_data = new byte[Layer3Netif.MTU];

                EndPoint server = dns.LocalEndPoint;
                dns.BeginReceiveFrom(response_data, 0,
                     response_data.Length, SocketFlags.None, ref server, (ar) =>
                     {
                         using (dns)
                         {
                             do
                             {
                                 try
                                 {
                                     int response_length = dns.EndReceiveFrom(ar, ref server);
                                     if (response_length <= 0)
                                     {
                                         break;
                                     }

                                     DnsResponse response = DnsResponse.From(response_data, response_length);
                                     if (response == null)
                                     {
                                         break;
                                     }

                                     answer?.Invoke(new BufferSegment(response_data, 0, response_length), response);
                                 }
                                 catch (Exception) { }
                             } while (false);
                             dns.Close();
                         }
                     }, null);
                return true;
            }
            catch (Exception)
            {
                dns.Close();
                dns.Dispose();
                return false;
            }
        }

        private DnsResponse CreateResponse(DnsRequest request, IPAddress address)
        {
            if (request == null || address == null)
            {
                return null;
            }

            DnsResponse response = CreateResponse(request.QueryID);
            response.Questions.Add(new ResourceRecord(request.Domain, request.QueryType, request.QueryClass, 127));
            response.Answers.Add(new Address(request.Domain, request.QueryType, request.QueryClass, 127, address.ToString()));
            return response;
        }

        public virtual string GetVirtualAddressHostName(IPAddress address)
        {
            this.m_poDnsMapFar.TryGetValue(address, out string hostname);
            return hostname ?? string.Empty;
        }

        protected virtual bool OnRequest(DnsRequest request, EndPoint remoteEP)
        {
            var pac = this.m_poTUN2Socks.GetPAC();
            if (!pac.IsReady())
            {
                return this.SuperiorAcquired(request, (message, response) => this.SendTo(response.ToArray(), remoteEP));
            }
            lock (this.m_poDnsMap)
            {
                this.m_poDnsMap.TryGetValue(request.Domain, out IPAddress address);
                if (address != null)
                {
                    return this.SendTo(this.CreateResponse(request, address).ToArray(), remoteEP);
                }
            }
            return this.SuperiorAcquired(request, (message, response) =>
            {
                string hijacked = string.Empty;
                lock (this.m_poDnsMap)
                {
                    //var addresses = DnsResponse.GetAddresses(response.Answers);
                    //if (!this.IsNotAllowAgent(addresses))
                    {
                        hijacked = "[:hijacked] ";

                        IPAddress address = this.NewVirtualAddress();
                        {
                            this.m_poDnsMap[request.Domain] = address;
                            this.m_poDnsMapFar[address] = request.Domain;
                        }
                        response = this.CreateResponse(request, address);
                    }
                }

                TUN2Socks.PrintTraceLine($"NSLookup[{request.QueryType}, {request.QueryClass}]: {request.Domain} {hijacked}-> {string.Join(" ", DnsResponse.FetchAddresses(response.Answers))}");
                this.SendTo(response.ToArray(), remoteEP);
            });
        }

        protected virtual bool IsNotAllowAgent(IEnumerable<IPAddress> s)
        {
            if (s == null)
            {
                return false;
            }
            var pac = this.m_poTUN2Socks.GetPAC();
            foreach (IPAddress address in s)
            {
                if (pac.IsNotAllowAgent(address))
                {
                    return true;
                }
            }
            return false;
        }

        protected virtual bool SendTo(BufferSegment message, EndPoint remoteEP)
        {
            lock (this.m_syncobj)
            {
                if (this.m_disposed)
                {
                    return false;
                }
                try
                {
                    int sent_bytes = this.m_poSocket.
                        SendTo(message.Buffer, message.Offset, message.Length, SocketFlags.None, remoteEP);
                    return sent_bytes > 0;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        protected virtual DnsResponse CreateResponse(int queryID)
        {
            return new DnsResponse
            {
                QueryID = queryID,
                AuthorativeAnswer = false,
                IsTruncated = false,
                RecursionRequested = true,
                RecursionAvailable = true,
                ResponseCode = ResponseCodes.NoError
            };
        }

        protected virtual void OnResponse(DnsResponse response, EndPoint remoteEP)
        {

        }

        public virtual bool Run()
        {
            lock (this.m_syncobj)
            {
                if (this.m_disposed)
                {
                    return false;
                }

                if (this.m_poListenThread == null)
                {
                    this.m_poListenThread = new Thread(() =>
                    {
                        while (!this.m_disposed)
                        {
                            try
                            {
                                EndPoint remoteEP = this.m_poSocket.LocalEndPoint;
                                int recv_bytes = this.m_poSocket.
                                    ReceiveFrom(this.m_szBuffer, 0, this.m_szBuffer.Length, SocketFlags.None, ref remoteEP);
                                ProcessRequest(this.m_szBuffer, 0, recv_bytes, remoteEP);
                            }
                            catch (Exception)
                            {
                                
                            }
                        }
                    })
                    { IsBackground = true, Priority = ThreadPriority.Lowest };
                    this.m_poListenThread.Start();
                }

                return this.m_poListenThread.ThreadState == ThreadState.Running;
            }
        }

        public virtual void Dispose()
        {
            lock (this.m_syncobj)
            {
                if (!this.m_disposed)
                {
                    this.m_disposed = true;
                    this.m_poSocket.Close();
                    this.m_poSocket.Dispose();
                }
            }
            GC.SuppressFinalize(this);
        }
    }
}
