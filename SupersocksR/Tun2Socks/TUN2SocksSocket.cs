namespace SupersocksR.Tun2Socks
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading;
    using SupersocksR.Core;
    using SupersocksR.Net;
    using SupersocksR.Net.Tun;
    using Socket = System.Net.Sockets.Socket;
    using SOCKET = SupersocksR.Net.Socket;

    public class TUN2SocksSocket : SOCKET 
    {
        private readonly TUN2Socks m_tun2socks;
        private Socket m_server;
        private int m_handshake_state = 0;
        private byte[] m_buffer = new byte[Layer3Netif.MSS];
        private int m_recv_concurrent = 0;
        private Queue<BufferSegment> m_messages = new Queue<BufferSegment>();

        public TUN2SocksSocket(TUN2Socks tun2socks, IPcb pcb) : base(pcb)
        {
            this.m_tun2socks = tun2socks ?? throw new ArgumentNullException(nameof(tun2socks));
        }

        public override void Close()
        {
            if (!Monitor.TryEnter(this))
            {
                Timer closer = null;
                closer = new Timer((state) =>
                {
                    closer.Dispose();
                    this.Close();
                });
                closer.Change(300, 0);
            }
            else
            {
                try
                {
                    try
                    {
                        Socket socket = this.m_server;
                        if (socket != null)
                        {
                            Shutdown(socket);
                            try
                            {
                                socket.Close();
                                socket.Dispose();
                            }
                            catch (Exception) { }
                            this.m_server = null;
                        }
                    }
                    catch (Exception) { }
                }
                finally
                {
                    Monitor.Exit(this);
                }
            }
            base.Close();
        }

        private bool SendAsync(byte[] buffer, int offset, int length)
        {
            bool closing = false;
            lock (this)
            {
                Socket socket = this.m_server;
                if (socket == null)
                {
                    closing = true;
                }
                else
                {
                    try
                    {
                        socket.BeginSend(buffer, offset, length, 0, out SocketError error, (ar) =>
                        {
                            try
                            {
                                socket.EndSend(ar, out error);
                                if (error != SocketError.Success)
                                {
                                    closing = true;
                                }
                            }
                            catch (Exception)
                            {
                                closing = true;
                            }
                            if (closing)
                            {
                                this.Close();
                            }
                        }, null);
                        if (error != SocketError.Success && error != SocketError.IOPending)
                        {
                            closing = true;
                        }
                    }
                    catch (Exception)
                    {
                        closing = true;
                    }
                }
            }
            if (closing)
            {
                this.Close();
            }
            return !closing;
        }

        private void HandshakeToServerAsync()
        {
            this.m_handshake_state = 0;
            using (MemoryStream message = new MemoryStream())
            {
                using (BinaryWriter message_writer = new BinaryWriter(message))
                {
                    message.WriteByte(0x05);
                    message.WriteByte(0x01);
                    message.WriteByte(0x00);

                    message.WriteByte(0x05); // VAR 
                    message.WriteByte(0x01); // CMD 
                    message.WriteByte(0x00); // RSV 

                    IPEndPoint server = ((IPEndPoint)this.RemoteEndPoint);
                    string domain = this.m_tun2socks.GetDnss().GetVirtualAddressHostName(server.Address);
                    if (string.IsNullOrEmpty(domain))
                    {
                        if (server.AddressFamily == AddressFamily.InterNetwork)
                        {
                            message.WriteByte(0x01); // ATYPE(IPv4)
                            message_writer.Write(server.Address.GetAddressBytes()); // ADDR
                        }
                        else if (server.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            message.WriteByte(0x04); // ATYPE(IPv6)
                            message_writer.Write(server.Address.GetAddressBytes()); // ADDR
                        }
                    }
                    else
                    {
                        message.WriteByte(0x03); // ATYPE(Domain)
                        byte[] domain_bytes = Encoding.UTF8.GetBytes(domain);
                        byte domain_bytes_size = (byte)Math.Min(domain_bytes.Length, 0xff);
                        message.WriteByte(domain_bytes_size);
                        message.Write(domain_bytes, 0, domain_bytes_size);
                    }
                    message_writer.Write(Convert.ToUInt16((byte)(server.Port >> 8) | ((byte)server.Port) << 8)); // PORT


                    this.m_handshake_state = 1;
                    if (!this.SendAsync(message.GetBuffer(), 0, Convert.ToInt32(message.Position)))
                    {
                        this.Close();
                        return;
                    }

                    void HandshakeProtocol()
                    {
                        this.ReceiveAsync(m_buffer, 0, 10, (by, buffer, offset, length) =>
                        {
                            if (by < 10 || '\x05' != buffer[0] || '\x00' != buffer[1])
                            {
                                this.Close();
                            }
                            else
                            {
                                DoOpenConnection();
                            }
                        });
                    }

                    this.ReceiveAsync(m_buffer, 0, 2, (by, buffer, offset, length) =>
                    {
                        if (by < 2 || '\x05' != buffer[0] || '\x00' != buffer[1])
                        {
                            this.Close();
                        }
                        else
                        {
                            HandshakeProtocol();
                        }
                    });
                }
            }
        }

        private void DoOpenConnection()
        {
            lock (this)
            {
                this.m_handshake_state = 2;
                lock (this.m_messages)
                {
                    while (this.m_messages.Count > 0)
                    {
                        BufferSegment segment = this.m_messages.Dequeue();
                        if (segment == null)
                        {
                            continue;
                        }

                        this.SendAsync(segment.Buffer, segment.Offset, segment.Length);
                        base.OnMessage(segment);
                    }
                    this.m_messages.Clear();
                }
            }
            base.OnOpen(EventArgs.Empty);
            this.ReceiveAsyncWaitPending();
        }

        private void ReceiveAsyncWaitPending()
        {
            void ReceiveAsyncWaitAsync()
            {
                this.ReceiveAsync(m_buffer, 0, m_buffer.Length, (by, buffer, offset, length) =>
                {
                    this.Send(new BufferSegment(buffer, offset, by));
                    this.ReceiveAsyncWaitPending();
                });
            }
            if (Interlocked.Increment(ref this.m_recv_concurrent) < 100)
            {
                ReceiveAsyncWaitAsync();
            }
            else
            {
                Timer maxreceiver = null;
                maxreceiver = new Timer((state) =>
                {
                    maxreceiver.Dispose();
                    ReceiveAsyncWaitAsync();
                });
                maxreceiver.Change(0, 0);
            }
            Interlocked.Decrement(ref this.m_recv_concurrent);
        }

        private bool ReceiveAsync(byte[] buffer, int offset, int length, Action<int, byte[], int, int> callback)
        {
            bool closing = false;
            if (!Monitor.TryEnter(this))
            {
                return false;
            }
            else
            {
                try
                {
                    Socket socket = this.m_server;
                    if (socket == null)
                    {
                        closing = true;
                    }
                    else
                    {
                        socket.BeginReceive(buffer, offset, length, SocketFlags.None, out SocketError error, (ar) =>
                        {
                            try
                            {
                                int by = socket.EndReceive(ar, out error);
                                if (by <= 0 || error != SocketError.Success)
                                {
                                    closing = true;
                                }
                                else
                                {
                                    callback?.Invoke(by, buffer, offset, length);
                                }
                            }
                            catch (Exception)
                            {
                                closing = true;
                            }
                            if (closing)
                            {
                                this.Close();
                            }
                        }, null);
                        if (error != SocketError.Success && error != SocketError.IOPending)
                        {
                            closing = true;
                        }
                    }
                }
                catch (Exception)
                {
                    closing = true;
                }
                finally
                {
                    Monitor.Exit(this);
                }
            }

            if (closing)
            {
                this.Close();
            }
            return true;
        }

        protected override void OnOpen(EventArgs e)
        {
            lock (this)
            {
                var proxy = this.m_tun2socks.Server; 
                this.m_server = new Socket(proxy.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                this.m_server.BeginConnect(proxy, (ar) =>
                {
                    bool closeing = false;
                    try
                    {
                        Socket socket = this.m_server;
                        if (ar == null || socket == null)
                        {
                            closeing = true;
                        }
                        else
                        {
                            socket.EndConnect(ar);
                            HandshakeToServerAsync();
                        }
                    }
                    catch (Exception)
                    {
                        closeing = true;
                    }
                    if (closeing)
                    {
                        this.Close();
                    }
                }, null);
            }
        }

        protected override void OnMessage(BufferSegment e)
        {
            bool events = false;
            lock (this)
            {
                events = this.m_handshake_state >= 2;
                if (!events)
                {
                    lock (this.m_messages)
                    {
                        this.m_messages.Enqueue(e);
                    }
                }
                else
                {
                    this.SendAsync(e.Buffer, e.Offset, e.Length);
                }
            }
            if (events)
            {
                base.OnMessage(e);
            }
        }
    }
}
