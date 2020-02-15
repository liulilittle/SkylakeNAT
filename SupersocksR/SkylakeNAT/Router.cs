namespace SupersocksR.SkylakeNAT
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using SupersocksR.Core;
    using SupersocksR.Net.IP;
    using SupersocksR.Net.Tun;
    using Ethernet = SupersocksR.Net.Ethernet;
    using NAT = SupersocksR.Net.NAT;

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
#if !_USE_RC4_SIMPLE_ENCIPHER
            private readonly Encryptor _encryptor;
#endif
            public event EventHandler Abort;
            public event EventHandler<SkylakeNATMessage> Message;
            public event EventHandler Authentication;

            public Router Router { get; }

            public int Id { get; private set; }

            public IPAddress Address { get; set; }

            public SkylakeNATClient(Router nat, Socket socket)
            {
                this.Router = nat ?? throw new ArgumentNullException("You provide a null references to SkylakeNAT which is not permitted");
                this._socket = socket ?? throw new ArgumentNullException("You provide a null references to Socket which is not permitted");
#if !_USE_RC4_SIMPLE_ENCIPHER
                this._encryptor = new Encryptor(Encryptor.EncryptionNames[0], $"{nat.Key}{nat.Subtract}");
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
                        {
                            socket = this._socket;
                        }
                        if (socket == null)
                        {
                            return;
                        }
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
                            {
                                error = SocketError.Success;
                            }
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
                    if (Shutdown(this._socket))
                    {
                        events = true;
                        this._socket = null;
                    }
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

            protected virtual void OnAuthentication(EventArgs e)
            {
                this.Authentication?.Invoke(this, e);
            }

            protected virtual void OnAbort(EventArgs e)
            {
                this.Abort?.Invoke(this, e);
            }

            protected virtual void OnMessage(SkylakeNATMessage e)
            {
                this.Message?.Invoke(this, e);
            }

            public virtual bool Send(SkylakeNATMessage message)
            {
                if (message == null)
                {
                    return false;
                }
                Socket socket = null;
                lock (this._syncobj)
                {
                    socket = this._socket;
                    if (socket == null)
                    {
                        return false;
                    }
                }
                BufferSegment payload_segment = message.Payload;
#if !_USE_RC4_SIMPLE_ENCIPHER
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
                        {
                            this.CloseOrAbort();
                        }
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
            }

            public virtual void Dispose()
            {
                lock (this._syncobj)
                {
                    this._phdr = null;
                    this._fseek = 0;
                    this._fhdr = false;
                    this._message = null;
                    Shutdown(_socket);
                    this._socket = null;
                    lock (this.Router._sockets)
                    {
                        var rsv = this._rsv_current;
                        if (rsv != null)
                        {
                            var l = rsv.List;
                            if (l != null)
                            {
                                l.Remove(rsv);
                            }
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
            this._server = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            this._server.NoDelay = true;
            this._server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
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
                                {
                                    deleteCompletely = true;
                                }
                                else
                                {
                                    var node = socket._rsv_current;
                                    if (node != null)
                                    {
                                        var l = node.List;
                                        if (l != null)
                                        {
                                            l.Remove(node);
                                        }
                                        socket._rsv_current = null;
                                    }
                                    if (s.Count <= 0)
                                    {
                                        deleteCompletely = true;
                                    }
                                }
                            }
                            if (deleteCompletely)
                            {
                                _sockets.TryRemove(socket.Address, out s);
                            }
                        }
                        this.ProcessAbort(socket);
                    }
                }
            };
            this._onSocketMessage = (sender, e) =>
            {
                if (sender is SkylakeNATClient socket)
                {
                    this.ProcessMessage(socket, e);
                }
            };
            this._onAuthentication = (sender, e) =>
            {
                if (sender is SkylakeNATClient socket)
                {
                    this.ProcessAuthentication(socket);
                }
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

        protected virtual void ProcessAuthentication(SkylakeNATClient socket)
        {
            if (this.ResponseAuthentication(socket,
                IPAddress.Parse("10.8.3.7"),
                IPAddress.Parse("10.8.0.1"), IPAddress.Parse("8.8.8.8")))
            {
                lock (this._sockets)
                {
                    if (_sockets.TryGetValue(socket.Address,
                        out LinkedList<SkylakeNATClient> s) || s == null)
                    {
                        _sockets[socket.Address] =
                            s = new LinkedList<SkylakeNATClient>();
                    }
                    if (s != null)
                    {
                        socket._rsv_current = s.AddLast(socket);
                    }
                }
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
                while (node != null)
                {
                    var i = node.Value;
                    i?.Close();
                    node = node.Next;
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

        protected virtual bool SendMessageToClient(IPAddress address, Func<SkylakeNATMessage> message)
        {
            if (address == null || message == null)
                return false;
            SkylakeNATClient socket = this.GetClient(address, out int sessions);
            if (socket == null)
                return false;
            SkylakeNATMessage packet = message();
            if (!socket.Send(packet))
            {
                for (int i = 0; i < sessions; i++)
                {
                    socket = this.GetClient(address, out sessions);
                    if (socket == null)
                        break;
                    if (socket.Send(packet))
                        return true;
                }
            }
            return false;
        }

        protected virtual void PrivateOutput(IPFrame packet)
        {
            if (packet != null)
            {
                this.SendMessageToClient(packet.Destination, () =>
                    new SkylakeNATMessage(IPv4Layer.ToArray(packet))
                    {
                        Commands = Commands.NATCommands_kEthernetInput,
                    });
            }
        }

        public virtual void Listen(int backlog)
        {
            if (backlog <= 0)
            {
                backlog = 1;
            }
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
                        this._server.Listen(backlog);
                        this.StartAccept(null);
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

        protected virtual SkylakeNATClient CreateClient(Socket socket)
        {
            if (socket == null)
                return null;
            return new SkylakeNATClient(this, socket);
        }

        public virtual void Dispose()
        {
            lock (this._syncobj)
            {
                if (!this._disposed)
                {
                    this.Close();
                    this.Ethernet.Dispose();
                    this._disposed = true;
                }
            }
            GC.SuppressFinalize(this);
        }

        public virtual int Port { get; }
    }
}
