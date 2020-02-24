namespace SupersocksR.SkylakeNAT
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using SupersocksR.Core;
    using SupersocksR.Net.IP;
    using SupersocksR.Net.Tools;
    using SupersocksR.Net.Tun;
    using Ethernet = SupersocksR.Net.Ethernet;
    using NAT = SupersocksR.Net.NAT;
    using Timer = System.Timers.Timer;

    public unsafe class Router : IDisposable
    {
        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int shutdown(IntPtr s, [In]SocketShutdown how);

        public static bool Shutdown(Socket socket)
        {
            if (socket == null)
            {
                return false;
            }

            shutdown(socket.Handle, SocketShutdown.Both);
            socket.Close();
            socket.Dispose();
            return true;
        }

        public class SkylakeNATMessage : EventArgs
        {
            public Commands Commands { get; set; }

            public BufferSegment Payload { get; set; }

            public SkylakeNATMessage(BufferSegment payload)
            {
                this.Payload = payload ?? throw new ArgumentNullException(nameof(payload));
            }
        }

        public class SkylakeNATClient : IDisposable
        {
            private readonly object _syncobj = new object();
            private Socket _socket = null;
            private byte[] _phdr = new byte[sizeof(pkg_hdr)];
            private int _fseek = 0;
            private bool _fhdr = false;
            private byte[] _message = null;
            internal LinkedListNode<SkylakeNATClient> _rsv_current = null;
#if !_USE_RC4_SIMPLE_ENCIPHER || __USE_UDP_PAYLOAD_TAP_PACKET
            internal readonly Encryptor _encryptor;
#endif
            public event EventHandler Abort;
            public event EventHandler<SkylakeNATMessage> Message;
            public event EventHandler Authentication;

            public Router Router { get; }

            public int Id { get; private set; }

            public IPAddress Address { get; set; }

#if _USE_RC4_SIMPLE_ENCIPHER
            public EndPoint LocalEndPoint { get; internal set; }
#endif

#if !__USE_UDP_PAYLOAD_TAP_PACKET
            public SkylakeNATClient(Router nat, Socket socket)
#else
            public SkylakeNATClient(Router nat, Socket socket, int localId, EndPoint localEP)
#endif
            {
                this.Router = nat ?? throw new ArgumentNullException("You provide a null references to SkylakeNAT which is not permitted");
                this._socket = socket ?? throw new ArgumentNullException("You provide a null references to Socket which is not permitted");
#if !_USE_RC4_SIMPLE_ENCIPHER || __USE_UDP_PAYLOAD_TAP_PACKET
                this._encryptor = new Encryptor(Encryptor.EncryptionNames[0], $"{nat.Key}{nat.Subtract}");
#endif
#if __USE_UDP_PAYLOAD_TAP_PACKET
                this.Id = localId;
                this.LocalEndPoint = localEP;
#endif
            }

            ~SkylakeNATClient()
            {
                this.Dispose();
            }

            public virtual void Listen()
            {
                Exception exception = null;
                do
                {
                    lock (this._syncobj)
                    {
                        var socket = this._socket;
                        if (socket == null)
                        {
                            exception = new InvalidOperationException("An invalid current state causes the current operation to fail to complete");
                            break;
                        }
                        try
                        {
                            socket.SendBufferSize = 524288;
                            socket.ReceiveBufferSize = 524288;
                            this.StartReceive(null);
                        }
                        catch (Exception e)
                        {
                            exception = e;
                            break;
                        }
                    }
                } while (false);
                if (exception != null)
                {
                    throw exception;
                }
            }

            private void StartReceive(IAsyncResult ar)
            {
                SkylakeNATMessage message = null;
                SocketError error = SocketError.SocketError;
                try
                {
                    do
                    {
                        Socket socket = null;
                        lock (this._syncobj)
                            socket = this._socket;
                        if (socket == null)
                            return;
                        if (ar == null)
                        {
                            if (!_fhdr)
                                socket.BeginReceive(_phdr, 0, _phdr.Length, SocketFlags.None, out error, StartReceive, null);
                            else
                            {
                                int suplus = _message.Length - _fseek;
                                if (suplus >= Layer3Netif.MSS)
                                    suplus = Layer3Netif.MSS;
                                socket.BeginReceive(_message, _fseek, suplus, SocketFlags.None, out error, StartReceive, null);
                            }
                            if (error == SocketError.IOPending)
                                error = SocketError.Success;
                        }
                        else
                        {
                            int len = -1;
                            try
                            {
                                len = socket.EndReceive(ar, out error);
                            }
                            catch (Exception)
                            {
                                len = -1;
                            }
                            if (len <= 0)
                            {
                                error = SocketError.SocketError;
                                break;
                            }
                            else
                            {
                                bool completion = false;
                                if (!_fhdr)
                                {
                                    fixed (byte* pinned = _phdr)
                                    {
                                        pkg_hdr* pkg = (pkg_hdr*)pinned;
                                        if (len != sizeof(pkg_hdr) || pkg->fk != pkg_hdr.FK)
                                        {
                                            error = SocketError.SocketError;
                                            break;
                                        }
                                        if (0 == pkg->len)
                                            completion = true;
                                        else
                                        {
                                            _fseek = 0;
                                            _fhdr = true;
                                            _message = new byte[pkg->len];
                                        }
                                        error = SocketError.Success;
                                    }
                                }
                                else
                                {
                                    _fseek += len;
                                    if (_fseek >= _message.Length)
                                        completion = true;
                                    error = SocketError.Success;
                                }
                                if (completion)
                                {
                                    fixed (byte* pinned = _phdr)
                                    {
                                        pkg_hdr* pkg = (pkg_hdr*)pinned;
                                        if (0 == pkg->len)
                                            message = new SkylakeNATMessage(new BufferSegment(BufferSegment.Empty));
                                        else
                                            message = new SkylakeNATMessage(new BufferSegment(_message));
                                        if (0 == this.Id)
                                            this.Id = pkg->id;
                                        message.Commands = unchecked((Commands)pkg->cmd);
                                        _fseek = 0;
                                        _fhdr = false;
                                        _message = null;
                                    }
                                    error = SocketError.Success;
                                }
                            }
                        }
                    } while (false);
                }
                catch (Exception)
                {
                    error = SocketError.SocketError;
                }
                if (error != SocketError.Success)
                {
                    this.CloseOrAbort();
                }
                else if (ar != null)
                {
                    if (message != null)
                    {
                        BufferSegment segment = message.Payload;
#if !_USE_RC4_SIMPLE_ENCIPHER
                        if (segment.Length > 0)
                        {
                            segment = this._encryptor.Decrypt(segment);
                            message.Payload = segment;
                        }
#else
                        fixed (byte* pinned = segment.Buffer)
                            if (pinned != null)
                                RC4.rc4_crypt(this.Router.Key, pinned, segment.Length, this.Router.Subtract, 0);
#endif
                        if (message.Commands != Commands.NATCommands_kAuthentication)
                            this.OnMessage(message);
                        else
                            this.OnAuthentication(message);
                    }
                    this.StartReceive(null);
                }
            }

            public virtual void Close() => this.Dispose();

            private void CloseOrAbort()
            {
                bool events = false;
                lock (this._syncobj)
                {
#if !__USE_UDP_PAYLOAD_TAP_PACKET
                    if (Shutdown(this._socket))
                    {
                        events = true;
                        this._socket = null;
                    }
#endif
                    this._message = null;
                    this._phdr = null;
                    this._fseek = 0;
                    this._fhdr = false;
                }
                if (events)
                {
                    this.OnAbort(EventArgs.Empty);
                }
            }

            protected internal virtual void OnAuthentication(EventArgs e)
            {
                this.Authentication?.Invoke(this, e);
            }

            protected internal virtual void OnAbort(EventArgs e)
            {
                this.Abort?.Invoke(this, e);
            }

            protected internal virtual void OnMessage(SkylakeNATMessage e)
            {
                this.Message?.Invoke(this, e);
            }

            public virtual bool Send(SkylakeNATMessage message, int sent = 1)
            {
                if (message == null)
                    return false;
                Socket socket = null;
                lock (this._syncobj)
                {
                    socket = this._socket;
                    if (socket == null)
                        return false;
                }
                BufferSegment payload_segment = message.Payload;
#if !_USE_RC4_SIMPLE_ENCIPHER || __USE_UDP_PAYLOAD_TAP_PACKET
                if (payload_segment.Length > 0)
                    payload_segment = this._encryptor.Encrypt(payload_segment);
#endif
                int payload_size = payload_segment.Length;
                byte[] packet = new byte[sizeof(pkg_hdr) + payload_size];
                fixed (byte* pinned = packet)
                {
                    pkg_hdr* pkg = (pkg_hdr*)pinned;
                    pkg->fk = pkg_hdr.FK;
                    pkg->len = unchecked((ushort)payload_size);
                    pkg->cmd = unchecked((byte)message.Commands);
                    if (payload_size > 0)
                    {
                        byte* payload_data = sizeof(pkg_hdr) + pinned;
                        Marshal.Copy(payload_segment.Buffer, payload_segment.Offset, (IntPtr)payload_data, payload_size);
#if _USE_RC4_SIMPLE_ENCIPHER
                        RC4.rc4_crypt(this.Router.Key, payload_data, payload_size, this.Router.Subtract, 1);
#endif
                    }
                }
#if _USE_RC4_SIMPLE_ENCIPHER
                try
                {
                    if (sent <= 0)
                        sent = 1;
                    for (int i = 0; i < sent; i++)
                    {
                        socket.BeginSendTo(packet, 0, packet.Length, SocketFlags.None, this.LocalEndPoint, (ar) =>
                        {
                            try
                            {
                                socket.EndSendTo(ar);
                            }
                            catch (Exception) { }
                        }, null);
                    }
                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
#else
                SocketError error = SocketError.SocketError;
                try
                {
                    socket.BeginSend(packet, 0, packet.Length, SocketFlags.None, out error, (ar) =>
                    {
                        error = SocketError.SocketError;
                        try
                        {
                            socket.EndSend(ar, out error);
                        }
                        catch (Exception)
                        {
                            error = SocketError.SocketError;
                        }
                        if (error != SocketError.Success)
                            this.CloseOrAbort();
                    }, null);
                }
                catch (Exception)
                {
                    error = SocketError.SocketError;
                }
                if (error != SocketError.Success && error != SocketError.IOPending)
                {
                    this.CloseOrAbort();
                    return false;
                }
                return true;
#endif
            }

            public virtual void Dispose()
            {
                lock (this._syncobj)
                {
                    this._phdr = null;
                    this._fseek = 0;
                    this._fhdr = false;
                    this._message = null;
#if !_USE_RC4_SIMPLE_ENCIPHER
                    Shutdown(_socket);
#endif
                    this._socket = null;
                    lock (this.Router._sockets)
                    {
                        var rsv = this._rsv_current;
                        if (rsv != null)
                        {
                            var l = rsv.List;
                            if (l != null)
                                l.Remove(rsv);
                        }
                        this._rsv_current = null;
                    }
                    this.Abort = null;
                    this.Message = null;
                    this.Authentication = null;
                }
                GC.SuppressFinalize(this);
            }
        }

        public enum Commands : ushort
        {
            NATCommands_kAuthentication,
            NATCommands_kEthernetInput,
            NATCommands_kEthernetOutput,
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct pkg_hdr
        {
            public byte fk;
            public byte cmd;
            public ushort len;
            public int id;

            public const int FK = 0x2A;
        }

        private readonly object _syncobj = new object();
        private Socket _server = null;
        private bool _disposed = false;
        private readonly EventHandler _onSocketAbort = null;
        private readonly EventHandler<SkylakeNATMessage> _onSocketMessage = null;
        private readonly EventHandler _onAuthentication = null;
        private readonly ConcurrentDictionary<IPAddress, LinkedList<SkylakeNATClient>> _sockets
            = new ConcurrentDictionary<IPAddress, LinkedList<SkylakeNATClient>>();
        private readonly ConcurrentDictionary<int, IPAddress> _addressAllocation = new ConcurrentDictionary<int, IPAddress>();
        private readonly HashSet<IPAddress> _assignedAddresses = new HashSet<IPAddress>();
        private readonly IPAddress _dhcpServerAddress = IPAddress.Parse("10.8.0.1");
        private readonly IPAddress _dnsServerAddress = IPAddress.Parse("8.8.8.8");
        private readonly IPAddressRange _dhcpAddressAllocationRange = IPAddressRange.Parse("10.8.0.2-10.8.255.254");
#if __USE_UDP_PAYLOAD_TAP_PACKET
        private class NATClientContext
        {
            public SkylakeNATClient client = null;
            public Stopwatch agingsw = new Stopwatch();
        }
        private Timer _doAgingswNatClientContextTimer;
        private readonly byte[] _mssPacketBuffer = new byte[4 * Layer3Netif.MTU];
        private readonly ConcurrentDictionary<int, NATClientContext> _natClientTable = new ConcurrentDictionary<int, NATClientContext>();
#endif

        public Ethernet Ethernet { get; }

        public NAT NAT { get; }

        public string Key { get; }

        public int Subtract { get; }

        public Router(IPAddress ethernet, int port, string key, int subtract)
        {
            if (ethernet == null)
                throw new ArgumentNullException("It is not allowed to specify an ethernet card address with a null value");
            if (IPEndPoint.MinPort >= port || port > IPEndPoint.MaxPort)
                throw new ArgumentOutOfRangeException($"The port used to connect to the server is less than or equal to {IPEndPoint.MinPort} or greater than {IPEndPoint.MaxPort}");
            this.Port = port;
            this.Key = key;
            this.Subtract = subtract;
#if !__USE_UDP_PAYLOAD_TAP_PACKET
            this._server = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            this._server.NoDelay = true;
            this._server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
#else
            this._server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            this._server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
#endif
            this._server.Bind(new IPEndPoint(ethernet, port));
            this._onSocketAbort = (sender, e) =>
            {
                if (sender is SkylakeNATClient socket)
                {
                    socket.Close();
                    if (socket.Address != null)
                    {
                        lock (this._sockets)
                        {
                            bool deleteCompletely = false;
                            if (_sockets.TryGetValue(socket.Address, out LinkedList<SkylakeNATClient> s))
                            {
                                if (s == null)
                                    deleteCompletely = true;
                                else
                                {
                                    var node = socket._rsv_current;
                                    if (node != null)
                                    {
                                        var l = node.List;
                                        if (l != null)
                                            l.Remove(node);
                                        socket._rsv_current = null;
                                    }
                                    if (s.Count <= 0)
                                        deleteCompletely = true;
                                }
                            }
                            if (deleteCompletely)
                            {
                                _sockets.TryRemove(socket.Address, out s);
                                lock (_addressAllocation)
                                {
                                    _addressAllocation.TryRemove(socket.Id, out IPAddress address_x);
                                    if (socket.Address != null)
                                        _assignedAddresses.Remove(socket.Address);
                                    else if (address_x != null)
                                        _assignedAddresses.Remove(address_x);
                                }
                            }
                        }
                        this.ProcessAbort(socket);
                    }
                }
            };
            this._onSocketMessage = (sender, e) =>
            {
                if (sender is SkylakeNATClient socket)
                    this.ProcessMessage(socket, e);
            };
            this._onAuthentication = (sender, e) =>
            {
                if (sender is SkylakeNATClient socket)
                    this.ProcessAuthentication(socket);
            };
            // 建立以太网NAT链路工作引擎
#if NO_USAGE_PCAP_NET
            this.Ethernet = new Ethernet(ethernet, false);
#else
            this.Ethernet = new Ethernet(ethernet, true);
#endif
            this.NAT = new NAT(this.Ethernet.GetEthernetAddress());
            // 建立以太网NAT传入传出链路
            this.NAT.PublicOutput += (sender, e) => this.Ethernet.Output(e);
            this.NAT.PrivateOutput += (seder, e) => this.PrivateOutput(e);
            this.Ethernet.PublicInput += (sender, e) => this.NAT.PublicInput(e);
#if __USE_UDP_PAYLOAD_TAP_PACKET
            this._doAgingswNatClientContextTimer = new Timer();
            this._doAgingswNatClientContextTimer.Elapsed += (sender, e) =>
            {
                foreach (var kv in _natClientTable)
                {
                    bool freely = false;
                    var context = kv.Value;
                    if (context == null)
                        freely = true;
                    else
                    {
                        SkylakeNATClient clients = null;
                        lock (context)
                        {
                            if (context.agingsw.ElapsedMilliseconds >= 10000)
                            {
                                freely = true;
                                clients = context.client;
                            }
                        }
                        clients?.OnAbort(EventArgs.Empty);
                    }
                    if (freely)
                    {
                        lock (this._sockets)
                        {
                            SkylakeNATClient clients = context.client;
                            if (clients != null)
                            {
                                IPAddress address = IPAddress.Any;
                                lock (_addressAllocation)
                                {
                                    _addressAllocation.TryRemove(clients.Id, out address);
                                    if (address == null)
                                        address = clients.Address;
                                    if (address != null && !Ethernet.Equals(address, IPAddress.Any))
                                    {
                                        _assignedAddresses.Remove(address);
                                        _sockets.TryRemove(address, out LinkedList<SkylakeNATClient> linkedlist_xx);
                                    }
                                }
                            }
                            _natClientTable.TryRemove(kv.Key, out NATClientContext context_xx);
                        }
                    }
                }
            };
            this._doAgingswNatClientContextTimer.Interval = 500;
            this._doAgingswNatClientContextTimer.Start();
#endif
        }

        protected virtual SkylakeNATClient GetClient(IPAddress address, out int sessions)
        {
            sessions = 0;
            SkylakeNATClient socket = null;
            lock (this._sockets)
            {
                if (_sockets.TryGetValue(address, out LinkedList<SkylakeNATClient> s) && s != null)
                {
                    var node = s.First;
                    s.RemoveFirst();
                    s.AddLast(node);
                    socket = node.Value;
                    sessions = s.Count;
                }
            }
            return socket;
        }

        protected virtual void ProcessAbort(SkylakeNATClient socket)
        {
            this.NAT.Release(socket.Address);
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct NATAuthenticationResponse
        {
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct Dhcp
            {
                public uint local;
                public uint dhcp;
                public uint dns;
            }
            public Dhcp dhcp;
        }

        protected virtual IPAddress AddressAllocation(int id)
        {
            if (0 == id)
                return null;
            lock (_addressAllocation)
            {
                if (_addressAllocation.TryGetValue(id, out IPAddress address) && address != null)
                    return address;
                foreach (IPAddress i in _dhcpAddressAllocationRange.AsEnumerable())
                {
                    if (i == null)
                        continue;
                    fixed (byte* p = i.GetAddressBytes())
                    {
                        byte l = p[3];
                        if (l <= 1 || l >= 255)
                            continue;
                    }
                    if (_assignedAddresses.Contains(i))
                        continue;
                    _addressAllocation[id] = i;
                    _assignedAddresses.Add(i);
                    return i;
                }
            }
            return null;
        }

        protected virtual void ProcessAuthentication(SkylakeNATClient socket)
        {
            IPAddress localIP = this.AddressAllocation(socket.Id);
            if (localIP == null)
                socket.Close();
            else
            {
                if (this.ResponseAuthentication(socket, localIP, this._dhcpServerAddress, this._dnsServerAddress))
                {
                    lock (this._sockets)
                    {
                        if (!_sockets.TryGetValue(socket.Address, out LinkedList<SkylakeNATClient> s) || s == null)
                        {
                            s = new LinkedList<SkylakeNATClient>();
                            _sockets[socket.Address] = s;
#if __USE_UDP_PAYLOAD_TAP_PACKET
                            s.AddLast(socket);
#endif
                        }
#if !__USE_UDP_PAYLOAD_TAP_PACKET
                        if (s != null)
                            socket._rsv_current = s.AddLast(socket);
#endif
                    }
                }
#if __USE_UDP_PAYLOAD_TAP_PACKET
                Console.WriteLine($"[{DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")}] {socket.Id} {socket.Address} {socket.LocalEndPoint}");
#endif
            }
        }

        protected virtual bool CloseManyClient(IPAddress address)
        {
            if (address == null)
                return false;
            lock (this._sockets)
            {
                _sockets.TryRemove(address, out LinkedList<SkylakeNATClient> s);
                if (s == null)
                    return false;
                var node = s.First;
                SkylakeNATClient socket = null;
                while (node != null)
                {
                    var i = node.Value;
                    if (i != null)
                    {
                        socket = i;
                        i.Close();
                    }
                    node = node.Next;
                }
                if (socket != null)
                {
                    lock (_addressAllocation)
                    {
                        _addressAllocation.TryRemove(socket.Id, out IPAddress address_x);
                        if (socket.Address != null)
                            _assignedAddresses.Remove(socket.Address);
                        else if (address_x != null)
                            _assignedAddresses.Remove(address_x);
                    }
                }
                return true;
            }
        }

        protected virtual bool ResponseAuthentication(SkylakeNATClient socket, IPAddress local, IPAddress dhcp, IPAddress dns)
        {
            byte[] message = new byte[sizeof(NATAuthenticationResponse)];
            fixed (byte* pinned = message)
            {
                NATAuthenticationResponse* response = (NATAuthenticationResponse*)pinned;
                response->dhcp.local = (uint)Ethernet.GetAddress(local);
                response->dhcp.dhcp = (uint)Ethernet.GetAddress(dhcp);
                response->dhcp.dns = (uint)Ethernet.GetAddress(dns);
            }
            socket.Address = local;
            return socket.Send(new SkylakeNATMessage(new BufferSegment(message))
            {
                Commands = Commands.NATCommands_kAuthentication,
            });
        }

        protected virtual void ProcessMessage(SkylakeNATClient socket, SkylakeNATMessage message)
        {
            if (message.Commands == Commands.NATCommands_kEthernetOutput)
            {
                IPFrame packet = IPv4Layer.ParseFrame(message.Payload, false);
                if (packet != null)
                {
                    if (this._sockets.ContainsKey(packet.Source))
                        this.PrivateInput(socket, packet);
                    else
                        this.CloseManyClient(socket.Address);
                }
            }
        }

        protected virtual void PrivateInput(SkylakeNATClient socket, IPFrame packet)
        {
            this.NAT.PrivateInput(packet);
        }

        protected virtual bool Send(IPAddress address, Func<SkylakeNATMessage> message, int sent = 1)
        {
            if (address == null || message == null)
                return false;
            SkylakeNATClient socket = this.GetClient(address, out int sessions);
            if (socket == null)
                return false;
            SkylakeNATMessage packet = message();
            if (!socket.Send(packet, sent))
            {
                for (int i = 0; i < sessions; i++)
                {
                    socket = this.GetClient(address, out sessions);
                    if (socket == null)
                        break;
                    if (socket.Send(packet, sent))
                        return true;
                }
            }
            return false;
        }

        protected virtual bool PrivateOutput(IPFrame packet)
        {
            if (packet == null)
                return false;
            return this.Send(packet.Destination, () =>
                new SkylakeNATMessage(IPv4Layer.ToArray(packet))
                {
                    Commands = Commands.NATCommands_kEthernetInput,
                });
        }

        public virtual void Listen(int backlog)
        {
            if (backlog <= 0)
                backlog = 1;
            Exception exception = null;
            do
            {
                lock (this._syncobj)
                {
                    if (this._disposed)
                    {
                        exception = new ObjectDisposedException("Almost all managed and unmanaged resources held by the current object have been processed and released");
                        break;
                    }
                    if (this._server == null)
                    {
                        exception = new InvalidOperationException("The state of the current object invalidates the current operation");
                        break;
                    }
                    try
                    {
#if !__USE_UDP_PAYLOAD_TAP_PACKET
                        this._server.Listen(backlog);
                        this.StartAccept(null);
#else
                        this.ProcessReceiveFromUdp(null);
#endif
                    }
                    catch (Exception e)
                    {
                        exception = e;
                    }
                }
            } while (false);
            if (exception != null)
            {
                throw exception;
            }
            this.Ethernet.Listen();
        }

#if __USE_UDP_PAYLOAD_TAP_PACKET
        private void ProcessReceiveFromUdp(IAsyncResult ar)
        {
            lock (this._syncobj)
            {
                try
                {
                    if (this._disposed)
                        return;
                    if (ar == null)
                    {
                        EndPoint remoteEP = this._server.LocalEndPoint;
                        this._server.BeginReceiveFrom(_mssPacketBuffer, 0, _mssPacketBuffer.Length, 0, ref remoteEP, ProcessReceiveFromUdp, null);
                    }
                    else
                    {
                        EndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);
                        int bytes = this._server.EndReceiveFrom(ar, ref remoteEP);
                        do
                        {
                            if (bytes < sizeof(pkg_hdr))
                                break;
                            fixed (byte* pinned = _mssPacketBuffer)
                            {
                                pkg_hdr* pkg = (pkg_hdr*)pinned;
                                if (pkg->fk != pkg_hdr.FK)
                                    break;
                                if ((pkg->len + sizeof(pkg_hdr)) != bytes)
                                    break;
                                if (pkg->id == 0)
                                    break;
                                Commands commands = unchecked((Commands)pkg->cmd);
                                if (commands == Commands.NATCommands_kAuthentication)
                                {
                                    NATClientContext context = null;
                                    SkylakeNATClient client = null;
                                    lock (this._sockets)
                                    {
                                        if (!_natClientTable.TryGetValue(pkg->id, out context) || context == null)
                                        {
                                            client = this.CreateClient(pkg->id, remoteEP);
                                            if (client != null)
                                            {
                                                client.LocalEndPoint = remoteEP;
                                                context = new NATClientContext()
                                                {
                                                    client = client
                                                };
                                                _natClientTable[pkg->id] = context;
                                                client.Abort += this._onSocketAbort;
                                                client.Message += this._onSocketMessage;
                                                client.Authentication += this._onAuthentication;
                                            }
                                        }
                                        else
                                        {
                                            client = context.client;
                                        }
                                    }
                                    if (context != null && client != null)
                                    {
                                        lock (context)
                                        {
                                            context.agingsw.Restart();
                                        }
                                        client.LocalEndPoint = remoteEP;
                                        client.OnAuthentication(EventArgs.Empty);
                                    }
                                }
                                else
                                {
                                    SkylakeNATClient client = null;
                                    lock (this._sockets)
                                    {
                                        _natClientTable.TryGetValue(pkg->id, out NATClientContext context);
                                        if (context != null)
                                        {
                                            lock (context)
                                            {
                                                context.agingsw.Restart();
                                            }
                                            client = context.client;
                                        }
                                    }
                                    if (client != null)
                                    {
                                        BufferSegment payload = null;
                                        if (pkg->len > 0)
                                        {
                                            int ofs = sizeof(pkg_hdr);
#if _USE_RC4_SIMPLE_ENCIPHER
                                            fixed (byte* payloadPtr = &_mssPacketBuffer[ofs])
                                                RC4.rc4_crypt(this.Key, payloadPtr, pkg->len, this.Subtract, 0);
#endif
                                            payload = client._encryptor.Decrypt(new BufferSegment(_mssPacketBuffer, ofs, pkg->len));
                                        }
                                        else
                                        {
                                            payload = new BufferSegment(BufferSegment.Empty);
                                        }
                                        client.OnMessage(new SkylakeNATMessage(payload)
                                        {
                                            Commands = commands,
                                        });
                                    }
                                }
                            }
                        } while (false);
                        this.ProcessReceiveFromUdp(null);
                    }
                }
                catch (Exception)
                {
                    this.ProcessReceiveFromUdp(null);
                }
            }
        }
#endif

#if !__USE_UDP_PAYLOAD_TAP_PACKET
        private void StartAccept(IAsyncResult ar)
        {
            lock (this._syncobj)
            {
                try
                {
                    if (this._disposed)
                    {
                        return;
                    }
                    if (ar == null)
                    {
                        this._server.BeginAccept(StartAccept, null);
                    }
                    else
                    {
                        Socket socket = this._server.EndAccept(ar);
                        if (socket != null)
                        {
                            SkylakeNATClient client = CreateClient(socket);
                            if (socket == null)
                            {
                                Shutdown(socket);
                            }
                            else
                            {
                                client.Abort += this._onSocketAbort;
                                client.Message += this._onSocketMessage;
                                client.Authentication += this._onAuthentication;
                                client.Listen();
                            }
                        }
                        this.StartAccept(null);
                    }
                }
                catch (Exception)
                {
                    this.CloseOrAbort(true);
                }
            }
        }
#endif

        private void CloseOrAbort(bool aborting)
        {
            bool events = false;
            lock (this._syncobj)
            {
                if (this._server != null)
                {
                    events = true;
                    this._server.Close();
                    this._server.Dispose();
                    this._server = null;
                }
            }
            if (aborting && events)
            {
                this.OnAbort(EventArgs.Empty);
            }
        }

        public virtual void Close() => this.CloseOrAbort(true);

        protected virtual void OnAbort(EventArgs e)
        {

        }

#if !__USE_UDP_PAYLOAD_TAP_PACKET
        protected virtual SkylakeNATClient CreateClient(Socket socket)
        {
            if (socket == null)
                return null;
            return new SkylakeNATClient(this, socket);
        }
#else
        protected virtual SkylakeNATClient CreateClient(int localId, EndPoint localIP)
        {
            if (0 == localId)
                return null;
            return new SkylakeNATClient(this, this._server, localId, localIP);
        }
#endif

        public virtual void Dispose()
        {
            lock (this._syncobj)
            {
                if (!this._disposed)
                {
                    this.Close();
                    this.Ethernet.Dispose();
                    this._disposed = true;
#if __USE_UDP_PAYLOAD_TAP_PACKET
                    if (this._doAgingswNatClientContextTimer != null)
                    {
                        this._doAgingswNatClientContextTimer.Close();
                        this._doAgingswNatClientContextTimer.Dispose();
                        this._doAgingswNatClientContextTimer = null;
                    }
#endif
                    lock (this._sockets)
                    {
                        lock (this._addressAllocation)
                        {
                            this._natClientTable.Clear();
                            this._sockets.Clear();
                            this._addressAllocation.Clear();
                            this._assignedAddresses.Clear();
                        }
                    }
                }
            }
            GC.SuppressFinalize(this);
        }

        public virtual int Port { get; }
    }
}
