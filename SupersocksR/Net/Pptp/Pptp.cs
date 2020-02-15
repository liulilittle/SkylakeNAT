namespace SupersocksR.Net.Pptp
{
    using System;
    using System.IO;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Text;

    public unsafe class Pptp
    {
        private const int MSS = 1400;

        private AsyncCallback m_pStartReceiveBuffer;
        private byte[] m_pBuffer;
        private Socket m_pSocket;
        private byte m_bState;
        private PptpListener m_pListener;

        public Pptp(PptpListener listener, Socket socket)
        {
            this.m_pStartReceiveBuffer = StartReceiveBuffer;
            this.m_pSocket = socket;
            this.m_pListener = listener;
            this.m_pBuffer = new byte[MSS];
            this.StartReceiveBuffer(null);
        }

        private void StartReceiveBuffer(IAsyncResult ar)
        {
            Socket socket = m_pSocket;
            if (socket == null)
            {
                return;
            }
            try
            {
                if (ar == null)
                {
                    socket.BeginReceive(m_pBuffer, 0, MSS, 0, m_pStartReceiveBuffer, null);
                }
                else
                {
                    int len = socket.EndReceive(ar, out SocketError error);
                    if (error != SocketError.Success)
                    {
                        len = ~0;
                    }
                    if (len <= 0)
                    {
                        CloseOrAbort(true);
                    }
                    else
                    {
                        ProcessReceived(m_pBuffer, len);
                        StartReceiveBuffer(null);
                    }
                }
            }
            catch (Exception)
            {
                CloseOrAbort(true);
            }
        }

        private int CloseOrAbort(bool abort)
        {
            Socket socket = m_pSocket;
            int error = -1001;
            if (socket != null)
            {
                try
                {
                    socket.Shutdown(SocketShutdown.Both);
                }
                catch (Exception) { }
                socket.Close();
                socket.Dispose();
                error = 0;
            }
            m_pSocket = null;
            return error;
        }

        private static ushort ntohs(ushort s)
        {
            byte* p = (byte*)&s;
            return (ushort)(p[0] << 8 | p[1]);
        }

        private static uint ntohl(uint s)
        {
            byte* p = (byte*)&s;
            return (uint)(p[0] << 24 | p[2] << 16 | p[3] << 8 | p[4]);
        }

        private class StartControlConnectionRequest // 156字节（至少）
        {
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct SCCRC
            {
                public ushort Length;                   // 帧长
                public ushort PPTPMessageType;          // 1、控制消息；2、管理信息
                public uint MagicCookie;                // 保留：0x1A2B3C4D
                public ushort ControlMessageType;       // 1
                public ushort Reserved0;                // 0
                public ushort ProtocolVersion;          // 版本号
                public ushort Reserved1;                // 0
                public uint FramingCapabilities;        // 1、异步帧支持（Asynchronous Framing Supported）；2、同步帧支持（Synchronous Framing Supported）
                public uint BearerCapabilities;         // 1、模拟访问支持（Analog Access Supported）；2、数字访问支持（Digital access supported）
                public ushort MaximumChannels;          // 最大PPP通道数
                public ushort FirmwareRevision;         // 固件版本号
            };

            public SCCRC* ContextPtr;
            public string HostName;                     // 主机名 64octets
            public string VendorString;                 // 提供者 64octets

            public static StartControlConnectionRequest Parse(byte* p, int len)
            {
                if (null == p || len < 156)
                {
                    return null;
                }

                StartControlConnectionRequest request = new StartControlConnectionRequest();
                request.ContextPtr = unchecked((SCCRC*)p);

                int size = ntohs(request.ContextPtr->Length);
                if (size < 156)
                {
                    return null;
                }

                if (1 != ntohs(request.ContextPtr->ControlMessageType))
                {
                    return null;
                }

                sbyte * ofs = (sbyte*)(p + sizeof(SCCRC));
                request.HostName = new string(ofs, 0, 64).TrimEnd('\x0');
                request.VendorString = new string(ofs + 64, 0, 64).TrimEnd('\x0');
                return request;
            }
        }

        private class StartControlConnectionReply
        {
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct SCCRC
            {
                public ushort Length;                   // 帧长
                public ushort PPTPMessageType;          // 1、控制消息；2、管理信息
                public uint MagicCookie;                // 保留：0x1A2B3C4D
                public ushort ControlMessageType;       // 1
                public ushort Reserved0;                // 0
                public ushort ProtocolVersion;          // 版本号
                public byte ResultCode;                 // 表示建立channal是否成功的结果码，值为1表示成功，值为2表示通用错误，暗示着有问题。值为3表示channal已经存在，值为4表示请求者未授权，值为5表示请求的PPTP协议版本不支持。
                public byte ErrorCode;                  // 表示错误码，一般值为0，除非Result Code值为2，不同的错误码表示不同的含义。
                public uint FramingCapabilities;        // 1、异步帧支持（Asynchronous Framing Supported）；2、同步帧支持（Synchronous Framing Supported）
                public uint BearerCapabilities;         // 1、模拟访问支持（Analog Access Supported）；2、数字访问支持（Digital access supported）
                public ushort MaximumChannels;          // 最大PPP通道数
                public ushort FirmwareRevision;         // 固件版本号
            };

            public SCCRC Context;
            public string HostName;                     // 主机名 64octets
            public string VendorString;                 // 提供者 64octets

            public MemoryStream Serialize()
            {
                MemoryStream ms = new MemoryStream(sizeof(SCCRC) + 64 * 2);
                byte[] buffer = new byte[sizeof(SCCRC)];
                fixed (byte* p = buffer)
                {
                    *(SCCRC*)p = this.Context;
                }
                byte[] sz1 = Encoding.UTF8.GetBytes(HostName.PadRight(64, '\x0'));
                byte[] sz2 = Encoding.UTF8.GetBytes(VendorString.PadRight(64, '\x0'));
                ms.Write(buffer, 0, buffer.Length);
                ms.Write(sz1, 0, sz1.Length);
                ms.Write(sz2, 0, sz2.Length);
                return ms;
            }
        }

        protected virtual bool SendMessage(byte[] buffer, int offset, int length)
        {
            Socket socket = m_pSocket;
            if (socket == null)
            {
                return false;
            }

            try
            {
                SocketError error = SocketError.SocketError;
                socket.BeginSend(buffer, offset, length, 0, out error, null, null);
                return error == SocketError.Success;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private int ProcessReceived(byte[] buffer, int len)
        {
            if (buffer == null)
            {
                CloseOrAbort(true);
                return -2001;
            }

            if (buffer.Length <= 0)
            {
                CloseOrAbort(true);
                return -2002;
            }

            if (len == 0)
            {
                CloseOrAbort(false);
                return -2003;
            }
            else if (len < 0)
            {
                CloseOrAbort(true);
                return -2004;
            }

            if (m_bState == 0)
            {
                return HandleConnectionRequest(buffer, len);
            }
            else if (m_bState == 1)
            {
                return HandleOutgoingCallRequest(buffer, len);
            }
            else if (m_bState == 2)
            {
                int HR = HandleSetLinkInfo(buffer, len);
                m_bState++;
                return HR;
            }
            else if (m_bState == 3)
            {
                int HR = HandleSetLinkInfo(buffer, len);
                fixed (byte* p = buffer)
                {
                    SetLinkInfo* o = (SetLinkInfo*)p;
                    o->PeersCallID = ntohs(RasdialClient.PeersCallId);
                    o->Reserved0 = ntohs(RasdialClient.SelfCallId);
                }
                SendMessage(buffer, 0, sizeof(SetLinkInfo));
                m_bState++;
                return HR;
            }
            else
            {
                return 0;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct SetLinkInfo
        {
            public ushort Length;
            public ushort PPTPMessageType;
            public uint MagicCookie;
            public ushort ControlMessageType;
            public ushort Reserved0;
            public ushort PeersCallID;
            public ushort Reserved1;
            public uint SendACCM;
            public uint ReceiveACCM;
        }

        private int HandleSetLinkInfo(byte[] buffer, int len)
        {
            fixed (byte* p = buffer)
            {
                SetLinkInfo* o = (SetLinkInfo*)p;
                if (len < 24)
                {
                    return -2201;
                }

                if (ntohs(o->Length) < 24)
                {
                    return -2201;
                }

                if (15 != ntohs(o->ControlMessageType))
                {
                    return -2202;
                }

                RasdialClient.SendACCM = o->SendACCM;
                RasdialClient.ReceiveACCM = o->ReceiveACCM;
            }

            return 0;
        }

        private class OutgoingCallRequest
        {
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct OCRC
            {
                public ushort Length;                   
                public ushort PPTPMessageType;          
                public uint MagicCookie;                
                public ushort ControlMessageType;       
                public ushort Reserved0;
                public ushort CallID;
                public ushort CallSerialNumber;
                public uint MinBPS;
                public uint MaxBPS;
                public uint BearerType;
                public uint FramingType;
                public ushort PacketRecvWindowSize;
                public ushort PacketProcessingDelay;
                public ushort PhoneNumberLength;
                public ushort Reserved1;
            }

            //public string PhoneNumber;
            //public string SubAddress;
        };

        public PptpRasdialClient RasdialClient { get; private set; }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct OutgoingCallReply
        {
            public ushort Length;
            public ushort PPTPMessageType;
            public uint MagicCookie;
            public ushort ControlMessageType;
            public ushort Reserved0;
            public ushort CallID;
            public ushort PeersCallID;
            public byte ResultCode;
            public byte ErrorCode;
            public ushort CauseCode;
            public uint ConnectSpeed;
            public ushort RevWindowSize;
            public ushort PacketProcessingDelay;
            public uint PhysicalChannelId;
        }

        protected virtual int HandleOutgoingCallRequest(byte[] buffer, int len)
        {
            fixed (byte* p = buffer)
            {
                OutgoingCallRequest.OCRC* o = (OutgoingCallRequest.OCRC*)p;
                if (len < 168)
                {
                    return -2101;
                }

                if (ntohs(o->Length) < 168)
                {
                    return -2101;
                }

                if (7 != ntohs(o->ControlMessageType))
                {
                    return -2102;
                }

                RasdialClient = m_pListener.CreateClient();
                RasdialClient.BindId = ntohs(o->CallSerialNumber);
                RasdialClient.PeersCallId = ntohs(o->CallID);
                RasdialClient.ReceiveBufferSize = ntohs(o->PacketRecvWindowSize);
                RasdialClient.MinBytesPerSecond = ntohl(o->MinBPS);
                RasdialClient.MaxBytesPerSecond = ntohl(o->MaxBPS);

                byte[] message = new byte[sizeof(OutgoingCallReply)];
                fixed (byte* pxm = message)
                {
                    OutgoingCallReply* r = (OutgoingCallReply*)pxm;
                    r->Length = ntohs((ushort)sizeof(OutgoingCallReply));
                    r->PPTPMessageType = o->PPTPMessageType;
                    r->ControlMessageType = ntohs(8);
                    r->PeersCallID = ntohs(RasdialClient.PeersCallId);
                    r->ResultCode = 1;
                    r->ErrorCode = 0;
                    r->CauseCode = 0;
                    r->Reserved0 = 0;
                    r->MagicCookie = o->MagicCookie;
                    r->ConnectSpeed = ntohl(RasdialClient.MaxBytesPerSecond);
                    r->RevWindowSize = ntohs((ushort)m_pSocket.ReceiveBufferSize);
                    r->PacketProcessingDelay = 0;
                    r->CallID = ntohs(RasdialClient.PeersCallId);
                    r->PhysicalChannelId = ntohl(RasdialClient.PhysicalChannelId);
                }

                SendMessage(message, 0, message.Length);
                m_bState++;
            }

            return 0;
        }

        protected virtual int HandleConnectionRequest(byte[] buffer, int len)
        {
            fixed (byte* p = buffer)
            {
                StartControlConnectionRequest request = StartControlConnectionRequest.Parse(p, len);
                if (request == null)
                {
                    return CloseOrAbort(true);
                }

                StartControlConnectionReply reply = new StartControlConnectionReply();
                fixed (StartControlConnectionReply.SCCRC* x = &reply.Context)
                {
                    *(StartControlConnectionRequest.SCCRC*)x = *request.ContextPtr;
                }

                reply.Context.BearerCapabilities = ntohl(2);
                reply.Context.ControlMessageType = ntohs(2);
                reply.Context.MaximumChannels = 0;
                reply.Context.FirmwareRevision = ntohs(3);

                reply.Context.ResultCode = 1;
                reply.Context.ErrorCode = 0;
                reply.HostName = request.HostName;
                reply.VendorString = request.VendorString;

                using (MemoryStream ms = reply.Serialize())
                {
                    byte[] message = ms.GetBuffer();
                    SendMessage(message, 0, unchecked((int)ms.Position));
                }

                m_bState++;
                return 0;
            }
        }
    }
}
