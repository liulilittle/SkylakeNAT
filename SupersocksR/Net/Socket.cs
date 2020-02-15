namespace SupersocksR.Net
{
    using System;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using SupersocksR.Core;

    public class Socket
    {
        private readonly IPcb m_poPCB = null;

        public event EventHandler Open;
        public event EventHandler Abort;
        public event EventHandler<BufferSegment> Message;

        public Socket(IPcb pcb)
        {
            this.m_poPCB = pcb ?? throw new ArgumentNullException(nameof(pcb));
            this.m_poPCB.Open += (sender, e) => this.OnOpen(e);
            this.m_poPCB.Abort += (sender, e) =>
            {
                this.OnAbort(e);
                this.Close();
            };
            this.m_poPCB.Message += (sender, e) => this.OnMessage(e);
        }

        public virtual AddressFamily AddressFamily => this.m_poPCB.AddressFamily;

        public virtual EndPoint RemoteEndPoint => this.m_poPCB.RemoteEndPoint;

        public virtual EndPoint LocalEndPoint => this.m_poPCB.LocalEndPoint;

        protected virtual void OnOpen(EventArgs e)
        {
            this.Open?.Invoke(this, e);
        }

        protected virtual void OnMessage(BufferSegment e)
        {
            this.Message?.Invoke(this, e);
        }

        protected virtual void OnAbort(EventArgs e)
        {
            this.Abort?.Invoke(this, e);
        }

        public virtual bool Send(BufferSegment buffer)
        {
            return this.m_poPCB.Send(buffer);
        }

        public virtual void Close()
        {
            this.m_poPCB.Close();
        }

        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int shutdown(IntPtr s, SocketShutdown how);

        public static void Shutdown(System.Net.Sockets.Socket socket)
        {
            if (socket == null)
            {
                return;
            }
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                shutdown(socket.Handle, SocketShutdown.Both);
            }
            else
            {
                try
                {
                    socket.Shutdown(SocketShutdown.Both);
                }
                catch (Exception) { }
            }
        }
    }
}
