namespace SupersocksR.Net
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Diagnostics;
    using System.Linq;
    using System.Linq.Expressions;
    using System.Net;
    using System.Net.NetworkInformation;
    using System.Net.Sockets;
    using System.Reflection;
    using System.Runtime.InteropServices;
    using System.Text;
#if !NO_USAGE_PCAP_NET
    using PcapDotNet.Core;
    using PcapDotNet.Packets;
    using PcapDotNet.Packets.Arp;
    using PcapDotNet.Packets.Ethernet;
    using PcapDotNet.Packets.IpV4;
#else
    using PcapDotNet.Packets.Ethernet;
#endif
    using SupersocksR.Core;
    using SupersocksR.Net.IP;
    using SupersocksR.Net.Tun;
    using AddressFamily = System.Net.Sockets.AddressFamily;
    using NSocket = System.Net.Sockets.Socket;

    public unsafe class Ethernet : IDisposable
    {
#if !NO_USAGE_PCAP_NET
        private readonly static Func<IpV4Datagram, int> g_getIPv4DatagramOffset = null;
        private readonly static Func<IpV4Datagram, byte[]> g_getIPv4DatagramBuffer = null;
#endif
        private readonly byte[] m_buffer = new byte[Layer3Netif.MTU];
        private readonly NSocket m_socket = null;
        private bool m_disposed = false;
        private readonly object m_syncobj = new object();
#if !NO_USAGE_PCAP_NET
        private readonly LivePacketDevice m_device = null;
        private readonly PacketCommunicator m_packetCommunicator = null;
#endif
        private readonly IPEndPoint m_ethernet = new IPEndPoint(IPAddress.Any, 0);
        private readonly ConcurrentDictionary<uint, ArpNetEntry> m_arpNetEntryTable = new ConcurrentDictionary<uint, ArpNetEntry>();
        private readonly Stopwatch m_arpNetEntryTableRefreshTime = new Stopwatch();

        public readonly static MacAddress MaxMacAddress = new MacAddress((PcapDotNet.Base.UInt48)0x0000ffFFffFFffFF);
        public readonly static MacAddress MinMacAddress = MacAddress.Zero;

#if !NO_USAGE_PCAP_NET
        static Ethernet()
        {
            ParameterExpression datagram = Expression.Parameter(typeof(IpV4Datagram), "datagram");
            g_getIPv4DatagramBuffer = Expression.Lambda<Func<IpV4Datagram, byte[]>>(
                Expression.Property(datagram, typeof(IpV4Datagram).GetProperty("Buffer", BindingFlags.NonPublic | BindingFlags.Instance)),
            datagram).Compile();
            g_getIPv4DatagramOffset = Expression.Lambda<Func<IpV4Datagram, int>>(
                Expression.Property(datagram, typeof(IpV4Datagram).GetProperty("StartOffset", BindingFlags.NonPublic | BindingFlags.Instance)),
            datagram).Compile();
        }
#endif

        public event EventHandler<IPFrame> PublicInput;
        public event EventHandler<IPFrame> PrivateInput;
        public event EventHandler<IPFrame> Sniffer;

        [DllImport("Iphlpapi.dll", SetLastError = false)]
        private static extern int SendARP(uint dest, uint host, ref long mac, ref int length);

        enum MIB_IPNET_TYPE
        {
            MIB_IPNET_TYPE_OTHER = 1,
            MIB_IPNET_TYPE_INVALID = 2,
            MIB_IPNET_TYPE_DYNAMIC = 3,
            MIB_IPNET_TYPE_STATIC = 4,
        }

        [StructLayout(LayoutKind.Sequential)]
        struct MIB_IPNETROW
        {
            /// <summary>
            /// The index of the adapter.
            /// </summary>
            public int dwIndex;
            /// <summary>
            /// The length, in bytes, of the physical address.
            /// </summary>
            public int dwPhysAddrLen;
            /// <summary>
            /// The physical address.
            /// </summary>
            public long bPhysAddr;
            /// <summary>
            /// The IPv4 address.
            /// </summary>
            public uint dwAddr;
            /// <summary>
            /// The type of ARP entry. This type can be one of the following values.
            /// </summary>
            public int dwType;
        }

        private class IPHelper
        {
            public const int NO_ERROR = 0;

            /// <summary>
            /// The buffer pointed to by the pIpNetTable parameter is not large enough.
            /// The required size is returned in the DWORD variable pointed to
            /// by the pdwSize parameter.
            /// </summary>
            public const int ERROR_INSUFFICIENT_BUFFER = 122;

            /// <summary>
            /// An invalid parameter was passed to the function. This error is returned
            /// if the pdwSize parameter is NULL, or GetIpNetTable is unable to write
            /// to the memory pointed to by the pdwSize parameter.
            /// </summary>
            public const int ERROR_INVALID_PARAMETER = 87;

            /// <summary>
            /// The IPv4 transport is not configured on the local computer.
            /// </summary>
            public const int ERROR_NOT_SUPPORTED = 50;

            public const int MAXLEN_PHYSADDR = 8;

            /// <summary>
            /// The GetIpNetTable function retrieves the IP-to-physical address mapping table.
            /// </summary>
            /// <param name="pIpNetTable">A pointer to a buffer that receives the
            ///        IP-to-physical address mapping table as a MIB_IPNETTABLE structure.</param>
            /// <param name="pdwSize">On input, specifies the size of the buffer pointed to
            /// by the pIpNetTable parameter.
            /// <para>On output, if the buffer is not large enough to hold the returned mapping table,
            /// the function sets this parameter equal to the required buffer size</para></param>
            /// <param name="bOrder">A Boolean value that specifies whether the returned mapping
            /// table should be sorted in ascending order by IP address. If this parameter is TRUE,
            /// the table is sorted.</param>
            /// <returns>If the function succeeds, the return value is NO_ERROR.
            /// <para>If the function fails, the return value is one of the following error codes:
            /// ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED or other code.
            /// </para>
            /// </returns>
            [DllImport("Iphlpapi.dll", EntryPoint = "GetIpNetTable")]
            public static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);
        }

        public class ArpNetEntry
        {
            public int IfIndex { get; set; }

            public bool Dynamic { get; set; }

            public IPAddress Address { get; set; }

            public MacAddress MacAddress { get; set; }

            public override string ToString()
            {
                return $"[{this.MacAddress}] {this.Address}";
            }
        }

        public static IPGlobalProperties GetIPGlobalProperties() => IPGlobalProperties.GetIPGlobalProperties();

        public static NetworkInterface[] GetAllNetworkInterfaces() => NetworkInterface.GetAllNetworkInterfaces();

        public static IEnumerable<ArpNetEntry> GetAllArpNetEntry()
        {
            IList<ArpNetEntry> arpEntries = new List<ArpNetEntry>();

            // The number of bytes needed.
            int bytesNeeded = 0;
            // The result from the API call.
            int result = IPHelper.GetIpNetTable(IntPtr.Zero, ref bytesNeeded, false);
            // Call the function, expecting an insufficient buffer.
            if (result != IPHelper.ERROR_INSUFFICIENT_BUFFER)
            {
                // Throw an exception.
                throw new Win32Exception(result);
            }
            // Allocate the memory, do it in a try/finally block, to ensure
            // that it is released.
            IntPtr buffer = IntPtr.Zero;

            // Try/finally.
            try
            {
                // Allocate the memory.
                buffer = Marshal.AllocCoTaskMem(bytesNeeded);
                // Make the call again. If it did not succeed, then
                // raise an error.
                result = IPHelper.GetIpNetTable(buffer, ref bytesNeeded, false);
                // If the result is not 0 (no error), then throw an exception.
                if (result != 0)
                {
                    // Throw an exception.
                    throw new Win32Exception(result);
                }
                // Now we have the buffer, we have to marshal it. We can read
                // the first 4 bytes to get the length of the buffer.
                int entries = Marshal.ReadInt32(buffer);
                // Increment the memory pointer by the size of the int.
                MIB_IPNETROW* mibi = (MIB_IPNETROW*)new IntPtr(buffer.ToInt64() +
                   Marshal.SizeOf(typeof(int)));

                for (int i = 0; i < entries; i++)
                {
                    MIB_IPNETROW* current = mibi + i;
                    bool dynamic_ = (MIB_IPNET_TYPE)current->dwType == MIB_IPNET_TYPE.MIB_IPNET_TYPE_DYNAMIC;
                    if (dynamic_
                        || (MIB_IPNET_TYPE)current->dwType == MIB_IPNET_TYPE.MIB_IPNET_TYPE_STATIC)
                    {
                        ArpNetEntry entry = new ArpNetEntry
                        {
                            Address = new IPAddress(current->dwAddr),
                            Dynamic = dynamic_,
                            IfIndex = current->dwIndex,
                            MacAddress = GetMacAddress((byte*)&current->bPhysAddr, current->dwPhysAddrLen),
                        };
                        arpEntries.Add(entry);
                    }
                }
            }
            finally
            {
                // Release the memory.
                Marshal.FreeCoTaskMem(buffer);
            }
            return arpEntries;
        }

        public static long SendARP(IPAddress address)
        {
            if (address == null || address.AddressFamily != AddressFamily.InterNetwork)
            {
                return 0;
            }
            uint host = BitConverter.ToUInt32(address.GetAddressBytes(), 0);
            try
            {
                long mac = 0;
                int len = 0;
                int rc = SendARP(host, 0, ref mac, ref len);
                if (rc != 0)
                {
                    return 0;
                }
                return mac;
            }
            catch (Exception)
            {
                return 0;
            }
        }

        public static MacAddress GetMacAddress(byte[] address)
        {
            if (address == null)
            {
                return MacAddress.Zero;
            }
            fixed (byte* p = address)
            {
                return GetMacAddress(p, address.Length);
            }
        }

        public static MacAddress GetMacAddress(byte* address, int address_size)
        {
            if (address == null || address_size <= 0)
            {
                return MacAddress.Zero;
            }
            long m = 0;
            byte* p = (byte*)&m;
            int l = Math.Min(address_size, sizeof(long));
            p += l;
            for (int i = 0; i < l; i++)
            {
                *--p = address[i];
            }
            return new MacAddress((PcapDotNet.Base.UInt48)m);
        }

        public static ArpNetEntry SearchingArpNetEntry(NetworkInterface interfaces) => SearchingArpNetEntry(interfaces, GetAllArpNetEntry());

        public static ArpNetEntry SearchingArpNetEntry(NetworkInterface interfaces, IEnumerable<ArpNetEntry> entries)
        {
            if (interfaces == null || entries == null)
            {
                return null;
            }
            foreach (IPAddress address in interfaces.GetIPProperties().DhcpServerAddresses.
                Union(interfaces.GetIPProperties().GatewayAddresses.Select(i => i.Address)))
            {
                if (address.AddressFamily != AddressFamily.InterNetwork)
                {
                    continue;
                }

                ArpNetEntry arpEntry = entries.FirstOrDefault(i =>
                {
                    if (!Equals(i.Address, address))
                    {
                        return false;
                    }

                    return i.MacAddress != MacAddress.Zero && i.MacAddress != MaxMacAddress;
                });
                if (arpEntry != null)
                {
                    return arpEntry;
                }
            }
            return null;
        }

#if !NO_USAGE_PCAP_NET
        public static LivePacketDevice SearchingLivePacketDevice(IPAddress ethernet)
        {
            if (ethernet == null)
                return null;
            return LivePacketDevice.AllLocalMachine.FirstOrDefault(i =>
            {
                if (i.Attributes != DeviceAttributes.None)
                    return false;
                return i.Addresses.FirstOrDefault(a =>
                {
                    if (a.Address.Family == (SocketAddressFamily)ethernet.AddressFamily)
                    {
                        IPAddress right = null;
                        if (a.Address is IpV4SocketAddress v4)
                            right = IPAddress.Parse(v4.Address.ToString());
                        else if (a.Address is IpV6SocketAddress v6)
                            right = IPAddress.Parse(v6.Address.ToString());
                        else
                            return false;
                        return Equals(ethernet, right);
                    }
                    return false;
                }) != null;
            });
        }
#endif

        public static int GetNetifIndex(NetworkInterface interfaces)
        {
            int index = ~0;
            if (interfaces != null)
            {
                Type type = interfaces.GetType();
                if (type == null)
                {
                    return index;
                }

                FieldInfo fi = type.GetField("index", BindingFlags.NonPublic | BindingFlags.Instance) ??
                    type.GetField("_index", BindingFlags.NonPublic | BindingFlags.Instance);
                if (fi == null)
                {
                    return index;
                }

                index = Convert.ToInt32(fi.GetValue(interfaces));
            }
            return index;
        }

        public Ethernet(IPAddress ethernet, bool supportTwoLayerLinks)
        {
            this.m_ethernet = new IPEndPoint(ethernet ??
                throw new ArgumentNullException("The ethernet card binding address you provided is an null references"), 0);
            this.SupportTwoLayerLinks = supportTwoLayerLinks;
            if (this.SupportTwoLayerLinks)
            {
#if NO_USAGE_PCAP_NET
                throw new NotSupportedException("The current ethernet instance is not SupportTwoLayerLinks");
#else
                this.m_device = SearchingLivePacketDevice(ethernet);
                if (this.m_device == null)
                {
                    throw new ArgumentOutOfRangeException("The ethernet card device bound to this address could not be found");
                }

                NetworkInterface networkInterface = this.GetNetworkInterface();
                if (networkInterface == null)
                {
                    throw new ArgumentOutOfRangeException("The NetworkInterface for the Ethernet device could not be found");
                }

                this.IfIndex = GetNetifIndex(networkInterface);
                this.LocalMacAddress = GetMacAddress(networkInterface.GetPhysicalAddress().GetAddressBytes());
                if (this.LocalMacAddress == MacAddress.Zero)
                {
                    throw new ArgumentOutOfRangeException("Unable to obtain the mac address of the current ethernet card");
                }

                ArpNetEntry arpNetEntry = SearchingArpNetEntry(networkInterface, this.GetArpNetEntryTable().Values);
                if (arpNetEntry == null)
                {
                    throw new ArgumentOutOfRangeException("The current ethernet card device cannot retrieve the arp network cache entry for its gateway");
                }
                else
                {
                    this.RemoteMacAddress = arpNetEntry.MacAddress;
                }

                this.m_packetCommunicator = this.m_device.Open(65536, PacketDeviceOpenAttributes.Promiscuous
                    | PacketDeviceOpenAttributes.MaximumResponsiveness, 1000);
                if (this.m_packetCommunicator == null)
                {
                    throw new InvalidOperationException("Unable to open ethernet card packet communication layer");
                }

                if (this.m_packetCommunicator.DataLink.Kind != DataLinkKind.Ethernet)
                {
                    throw new InvalidOperationException("This is not a valid ethernet card network character device");
                }
#endif
            }
            else
            {
                this.m_socket = new NSocket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                this.m_socket.Bind(this.m_ethernet);
                this.m_socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                this.m_socket.IOControl(IOControlCode.ReceiveAll, new byte[4] { 1, 0, 0, 0 }, new byte[4] { 1, 0, 0, 0 });
                this.m_socket.IOControl(IOControlCode.ReceiveAllMulticast, new byte[4] { 1, 0, 0, 0 }, new byte[4] { 1, 0, 0, 0 });
                this.m_socket.IOControl(IOControlCode.KeepAliveValues | IOControlCode.BindToInterface, new byte[1] { 0 }, new byte[1] { 0 });
            }
        }

        public bool SupportTwoLayerLinks { get; }

        public MacAddress LocalMacAddress { get; private set; }

        public MacAddress RemoteMacAddress { get; private set; }

        public int IfIndex { get; private set; }

#if !NO_USAGE_PCAP_NET
        public LivePacketDevice GetPacketDevice() => null;
#endif

        public IPAddress GetEthernetAddress() => this.m_ethernet.Address;

        public virtual void Dispose()
        {
            lock (this.m_syncobj)
            {
                if (!this.m_disposed)
                {
                    this.m_disposed = true;
#if !NO_USAGE_PCAP_NET
                    if (this.m_packetCommunicator != null)
                    {
                        this.m_packetCommunicator.Break();
                        this.m_packetCommunicator.Dispose();
                    }
#endif
                    if (this.m_socket != null)
                    {
                        try
                        {
                            this.m_socket.Shutdown(SocketShutdown.Both);
                        }
                        catch (Exception) { }
                        try
                        {
                            this.m_socket.Close();
                            this.m_socket.Dispose();
                        }
                        catch (Exception) { }
                    }
                }
            }
            GC.SuppressFinalize(this);
        }

        public NetworkInterface GetNetworkInterface()
        {
            return NetworkInterface.GetAllNetworkInterfaces().
                    FirstOrDefault(i => i.GetIPProperties().UnicastAddresses.FirstOrDefault(a => Equals(a.Address, this.m_ethernet.Address)) != null);
        }

#if !NO_USAGE_PCAP_NET
        protected virtual void NetifLevel2LayerIPv4(EthernetDatagram datagram, IpV4Datagram ip)
        {
            byte[] packet_data = g_getIPv4DatagramBuffer(ip);
            int packet_offset = g_getIPv4DatagramOffset(ip);
            int packet_size = ip.Length;
            if (packet_size > 0)
            {
                IPFrame frame = IPv4Layer.ParseFrame(new
                    BufferSegment(packet_data, packet_offset, packet_size), false);
                if (frame != null)
                {
                    frame.SourceMacAddress = datagram.Source;
                    frame.DestinationMacAddress = datagram.Destination;
                    this.OnSniffer(frame);
                }
            }
        }

        protected virtual void NetifLevel2LayerArp(EthernetDatagram datagram, ArpDatagram arp)
        {

        }
#endif
        public virtual void Listen()
        {
            while (true)
            {
                lock (this.m_syncobj)
                {
                    if (this.m_disposed)
                    {
                        break;
                    }
                }
                if (this.SupportTwoLayerLinks)
                {
#if !NO_USAGE_PCAP_NET
                    // Retrieve the packets
                    PacketCommunicatorReceiveResult result = this.m_packetCommunicator.ReceivePacket(out Packet packet);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout:
                            // Timeout elapsed
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            {
                                EthernetDatagram datagram = packet.Ethernet; // 以太网数据报
                                switch (datagram.EtherType)
                                {
                                    case EthernetType.IpV4:
                                        NetifLevel2LayerIPv4(datagram, datagram.IpV4);
                                        break;
                                    case EthernetType.IpV6:
                                        break;
                                    case EthernetType.Arp:
                                        NetifLevel2LayerArp(datagram, datagram.Arp);
                                        break;
                                    default:
                                        break;
                                }
                            }
                            break;
                        default:
                            break;
                    }
#endif
                }
                else
                {
                    int packet_size = 0;
                    try
                    {
                        EndPoint localEP = this.m_socket.LocalEndPoint;
                        packet_size = this.m_socket.ReceiveFrom(this.m_buffer, 0, this.m_buffer.Length, SocketFlags.None, ref localEP);
                    }
                    catch (Exception)
                    {
                        continue;
                    }

                    if (packet_size <= 0)
                    {
                        continue;
                    }

                    IPFrame frame = IPv4Layer.ParseFrame(new BufferSegment(this.m_buffer, 0, packet_size), false);
                    if (frame != null)
                    {
                        this.OnSniffer(frame);
                    }
                }
            }
        }

        public static long GetAddress(IPAddress address)
        {
            if (address == null)
            {
                return 0;
            }
            fixed (byte* pinned = address.GetAddressBytes())
            {
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    return *(uint*)pinned;
                }
                else if (address.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    return *(long*)pinned;
                }
                return 0;
            }
        }

        public static bool Equals(IPAddress x, IPAddress y)
        {
            if (x == null && y == null)
                return true;
            if (x.AddressFamily != y.AddressFamily)
                return false;

            byte[] bx = x.GetAddressBytes();
            byte[] by = y.GetAddressBytes();
            if (bx.Length != by.Length)
                return false;

            fixed (byte* pinnedX = bx)
            {
                fixed (byte* pinnedY = by)
                {
                    if (bx.Length == 4)
                        return *(uint*)pinnedX == *(uint*)pinnedY; // 32bit
                    else if (bx.Length == 8)
                        return *(ulong*)pinnedX == *(ulong*)pinnedY; // 64bit
                    else if (bx.Length == 16)
                        return *(decimal*)pinnedX == *(decimal*)pinnedY; // 128bit
                    else if (bx.Length == 2)
                        return *(ushort*)pinnedX == *(ushort*)pinnedY; // 16bit
                    else if (bx.Length == 1)
                        return *pinnedX == *pinnedY;
                    else
                    {
                        for (int i = 0; i < bx.Length; ++i)
                            if (pinnedX[i] != pinnedY[i])
                                return false;
                        return true;
                    }
                }
            }
        }

        protected virtual void OnSniffer(IPFrame frame)
        {
            this.Sniffer?.Invoke(this, frame);
            if (Equals(frame.Destination, this.m_ethernet.Address))
            {
                this.OnPublicInput(frame);
            }
            else
            {
                this.OnPrivateInput(frame);
            }
        }

        protected virtual void OnPrivateInput(IPFrame frame)
        {
            this.PrivateInput?.Invoke(this, frame);
        }

        protected virtual void OnPublicInput(IPFrame frame)
        {
            this.PublicInput?.Invoke(this, frame);
        }

        public virtual bool Output(IPFrame frame)
        {
            if (frame == null)
            {
                return false;
            }
            lock (this.m_syncobj)
            {
                if (this.m_disposed)
                {
                    return false;
                }
            }
            if (this.SupportTwoLayerLinks)
            {
#if NO_USAGE_PCAP_NET
                return false;
#else
                IList<ILayer> layers = ParseFrameToLayers(frame);
                if (layers == null || layers.Count <= 0)
                    return false;

                MacAddress sources = frame.SourceMacAddress;
                MacAddress destination = frame.DestinationMacAddress;
                if (sources == MinMacAddress)
                    sources = SelectMacAddress(frame.Source);
                if (destination == MinMacAddress)
                    destination = SelectMacAddress(frame.Destination);

                return this.SendNetifLevel2Output(layers: layers,
                    source: sources,
                    destination: destination);
#endif
            }
            else
            {
                return this.SendNetifLevel3Output(packet: IPv4Layer.ToArray(frame));
            }
        }

        public virtual IDictionary<uint, ArpNetEntry> GetArpNetEntryTable()
        {
            lock (this.m_arpNetEntryTable)
            {
                if (this.m_arpNetEntryTableRefreshTime.IsRunning &&
                    this.m_arpNetEntryTableRefreshTime.ElapsedMilliseconds < 1000)
                {
                    return this.m_arpNetEntryTable;
                }
                else
                {
                    this.m_arpNetEntryTableRefreshTime.Restart();
                }
                this.m_arpNetEntryTable.Clear();
                foreach (ArpNetEntry arp in GetAllArpNetEntry())
                {
                    if (arp == null || arp.Address.AddressFamily != AddressFamily.InterNetwork)
                    {
                        continue;
                    }
                    fixed (byte* pinned = arp.Address.GetAddressBytes())
                    {
                        uint key = *(uint*)pinned;
                        if (this.m_arpNetEntryTable.TryGetValue(key, out ArpNetEntry entry))
                        {
                            if (entry != null && entry.IfIndex == this.IfIndex)
                            {
                                continue;
                            }
                        }
                        this.m_arpNetEntryTable[key] = arp;
                    }
                }
                return this.m_arpNetEntryTable;
            }
        }

        public virtual MacAddress SelectMacAddress(IPAddress address)
        {
            if (address == null || address.AddressFamily != AddressFamily.InterNetwork)
            {
                return MinMacAddress;
            }
            var entities = this.GetArpNetEntryTable();
            fixed (byte* pinned = address.GetAddressBytes())
            {
                entities.TryGetValue(*(uint*)pinned, out ArpNetEntry entry);
                if (entry == null)
                {
                    if (Equals(this.m_ethernet.Address, address))
                    {
                        return this.LocalMacAddress;
                    }
                    return this.RemoteMacAddress;
                }
                return entry.MacAddress;
            }
        }

#if !NO_USAGE_PCAP_NET
        protected virtual ILayer ParseFrameToLayer(IPFrame frame)
        {
            BufferSegment packet = IPv4Layer.ToArray(frame);
            if (packet == null)
            {
                return null;
            }

            return new PayloadLayer()
            {
                Data = new Datagram(packet.Buffer, packet.Offset, packet.Length)
            };
        }

        protected virtual IList<ILayer> ParseFrameToLayers(IPFrame frame)
        {
            if (frame == null)
            {
                throw new ArgumentNullException(nameof(frame));
            }
            IList<ILayer> layers = new List<ILayer>();
            BufferSegment packet = IPv4Layer.ToArray(frame);
            if (packet != null)
            {
                layers.Add(new PayloadLayer()
                {
                    Data = new Datagram(packet.Buffer, packet.Offset, packet.Length)
                });
            }
            return layers;
        }

        protected virtual bool SendNetifLevel2Output(IList<ILayer> layers, MacAddress source, MacAddress destination)
        {
            if (layers == null || layers.Count <= 0)
            {
                return false;
            }
            layers.Insert(0, new EthernetLayer()
            {
                Source = source,
                Destination = destination,
                EtherType = EthernetType.IpV4, // Will be filled automatically.
            });
            Packet packet = PacketBuilder.Build(DateTime.Now, layers);
            if (packet == null)
            {
                return false;
            }
            fixed (byte* pinned = packet.Buffer)
            {
                if (pinned == null)
                {
                    return false;
                }
                try
                {
                    this.m_packetCommunicator.SendPacket(packet);
                }
                catch (Exception)
                {
                    return false;
                }
            }
            return true;
        }
#endif

        protected bool SendNetifLevel3Output(BufferSegment packet)
        {
            if (packet == null)
            {
                return false;
            }

            return SendNetifLevel3Output(packet.Buffer, packet.Offset, packet.Length);
        }

        protected virtual bool SendNetifLevel3Output(byte[] buffer, int offset, int length)
        {
            if (buffer == null ||
                buffer.Length <= 0 || offset < 0 || length < 0)
            {
                return false;
            }

            int boundary = unchecked(offset + length);
            if (boundary > buffer.Length)
            {
                return false;
            }

            EndPoint localEP = this.m_ethernet;
            try
            {
                return null !=
                    this.m_socket.BeginSendTo(buffer, offset, length, SocketFlags.None, localEP, (ar) =>
                    {
                        try
                        {
                            this.m_socket.EndSendTo(ar);
                        }
                        catch (Exception)
                        {

                        }
                    }, null);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
