namespace SupersocksR.Net.Tun
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net.NetworkInformation;
    using System.Reflection;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;
    using SupersocksR.Core;
    using SupersocksR.Net.Entry;
    using SupersocksR.Net.IP;

#pragma warning disable IDE1006
    public unsafe class Layer3Netif : INetif
    {
        private readonly object _syncobj = new object();
        private int _disposed = 0;

        public virtual IntPtr Handle { get; }

        public virtual IPLayer IPv4 { get; }

        public virtual int Index { get; }

        public virtual string Name { get; }

        public Layer3Netif(ILayerLocator locator, string componentId)
        {
            if (locator == null)
            {
                throw new ArgumentNullException(nameof(locator));
            }
            this.Handle = OpenTunDev(componentId);
            if (IntPtr.Zero == this.Handle)
            {
                throw new SystemException("Unable to open netif specifying componentId");
            }
            this.IPv4 = locator.IPv4;
            this.Index = GetAdapterIndex(componentId);
            this.Name = GetAdapterName(componentId);
        }

        private class NativeNetif
        {
            private static UIntPtr HKEY_LOCAL_MACHINE = new UIntPtr(0x80000002u);
            private static UIntPtr HKEY_CURRENT_USER = new UIntPtr(0x80000001u);
            private static UIntPtr NULL = UIntPtr.Zero;
            public const int ERROR_SUCCESS = 0;
            private const int KEY_ALL_ACCESS = 983103;
            private const int MAX_PATH = 260;
            private const uint REG_NONE = 0;
            private const int REG_SZ = 1;
            private const int RRF_RT_REG_SZ = 0x00000002;
            private const int FILE_FLAG_OVERLAPPED = 0x40000000;

            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
            public static extern bool ReadFile(IntPtr hFile,
                [MarshalAs(UnmanagedType.LPArray)]byte[] aSegementArray,
                int nNumberOfBytesToRead,
                ref int lpReserved, 
                [In] ref OVERLAPPED lpOverlapped); // System.Threading.NativeOverlapped

            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
            public static extern bool GetOverlappedResult(
                IntPtr hFile, 
                OVERLAPPED* lpOverlapped,
                ref int lpNumberOfBytesTransferred, 
                [MarshalAs(UnmanagedType.Bool)]bool bWait);

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
            public static extern IntPtr CreateEvent(IntPtr lpEventAttributes,
                [MarshalAs(UnmanagedType.Bool)]bool bManualReset,
                [MarshalAs(UnmanagedType.Bool)]bool bInitialState, 
                string lpName);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern int WaitForSingleObject(IntPtr hObject, int dwTimeout);

            [DllImport("advapi32.dll", CharSet = CharSet.Ansi)]
            private static extern int RegOpenKeyEx(
                    UIntPtr hKey,
                    string subKey,
                    int ulOptions,
                    int samDesired,
                    out UIntPtr hkResult);

            [DllImport("advapi32.dll", CharSet = CharSet.Ansi)]
            private extern static int RegEnumKey(UIntPtr hkey,
                    uint index,
                    byte[] lpName,
                    uint lpcbName);

            [DllImport("advapi32.dll", CharSet = CharSet.Ansi)]
            private extern static int RegOpenKey(UIntPtr hkey,
                string lpSubKey,
                out UIntPtr phkResult);

            [DllImport("advapi32.dll", CharSet = CharSet.Ansi)]
            private extern static int RegCloseKey(UIntPtr hkey);

            [DllImport("advapi32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
            private static extern int RegQueryValueEx(
                UIntPtr hKey,
                string lpValueName,
                int lpReserved,
                out uint lpType,
                byte[] lpData,
                ref int lpcbData);

            [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
            public static extern void* memset(void* dest, int c, int byteCount);

            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
            private static extern IntPtr CreateFile(
                        string filename,
                        [MarshalAs(UnmanagedType.U4)] FileAccess access,
                        [MarshalAs(UnmanagedType.U4)] FileShare share,
                        IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
                        [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
                        [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
                        IntPtr templateFile);

            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
            private static extern IntPtr CreateFile(
                        string filename,
                        int access,
                        int share,
                        IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
                        int creationDisposition,
                        int flagsAndAttributes,
                        IntPtr templateFile);

            [StructLayout(LayoutKind.Explicit, Pack = 1)]
            public struct OVERLAPPED
            {
                [FieldOffset(0)]
                public uint Internal;

                [FieldOffset(4)]
                public uint InternalHigh;

                [FieldOffset(8)]
                public uint Offset;

                [FieldOffset(12)]
                public uint OffsetHigh;

                [FieldOffset(8)]
                public IntPtr Pointer;

                [FieldOffset(16)]
                public IntPtr hEvent;
            }

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool DeviceIoControl(
                [MarshalAs(UnmanagedType.SysInt)]IntPtr hDevice, 
                uint dwIoControlCode,
                [MarshalAs(UnmanagedType.LPArray)]byte[] lpInBuffer, 
                uint nInBufferSize,
                [MarshalAs(UnmanagedType.LPArray)]byte[] lpOutBuffer,
                uint nOutBufferSize,
                ref uint lpBytesReturned, 
                ref OVERLAPPED lpOverlapped);

            public static ISet<string> FindAllComponentId()
            {
                string szOwnerKeyPath = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
                ISet<string> oDevComponentSet = new HashSet<string>();
                if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szOwnerKeyPath, 0, KEY_ALL_ACCESS, out UIntPtr hOwnerKey) == ERROR_SUCCESS)
                {
                    byte[] szClassName = new byte[MAX_PATH];
                    uint dwIndex = 0;
                    byte[] data = new byte[MAX_PATH];
                    while (RegEnumKey(hOwnerKey, dwIndex++, szClassName, MAX_PATH) == ERROR_SUCCESS)
                    {
                        uint dwRegType = REG_NONE;
                        int dwSize = data.Length;
                        UIntPtr hSubKey = NULL;
                        string szSubKeyPath = szOwnerKeyPath + "\\" + Encoding.Default.GetString(szClassName);
                        if (RegOpenKey(HKEY_LOCAL_MACHINE, szSubKeyPath, out hSubKey) != ERROR_SUCCESS)
                        {
                            continue;
                        }
                        if (RegQueryValueEx(hSubKey, "ComponentId", 0, out dwRegType, data, ref dwSize) == ERROR_SUCCESS && dwRegType == REG_SZ)
                        {
                            if (dwSize < 3)
                            {
                                continue;
                            }
                            string szData = Encoding.Default.GetString(data, 0, 3).TrimEnd();
                            if ("tap" == szData)
                            {
                                dwSize = data.Length;
                                dwRegType = 0;
                                if (RegQueryValueEx(hSubKey, "NetCfgInstanceId", 0, out dwRegType, data, ref dwSize) == ERROR_SUCCESS && dwRegType == REG_SZ)
                                {
                                    string szDevComponentId = dwSize <= 0 ? string.Empty : Encoding.Default.GetString(data, 0, dwSize - 1).TrimEnd();
                                    if (!string.IsNullOrEmpty(szDevComponentId))
                                    {
                                        oDevComponentSet.Add(szDevComponentId);
                                    }
                                }
                            }
                        }
                        RegCloseKey(hSubKey);
                    }
                    RegCloseKey(hOwnerKey);
                }
                return oDevComponentSet;
            }

            private const int GENERIC_READ                      = unchecked((int)(0x80000000));
            private const int GENERIC_WRITE                     = (0x40000000);
            private const int FILE_SHARE_READ                   = 0x00000001;
            private const int FILE_SHARE_WRITE                  = 0x00000002;
            private const int OPEN_EXISTING                     = 3;
            private const int FILE_ATTRIBUTE_SYSTEM             = 0x00000004;

            public static IntPtr OpenDrive(string drive)
            {
                IntPtr handle = CreateFile(drive,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_SYSTEM,
                    IntPtr.Zero);
                if (handle == IntPtr.Zero || handle == (IntPtr)~0)
                {
                    handle = CreateFile(drive,
                            FileAccess.ReadWrite,
                            FileShare.ReadWrite,
                            IntPtr.Zero,
                            FileMode.Open,
                            FileAttributes.System | (FileAttributes)FILE_FLAG_OVERLAPPED,
                            IntPtr.Zero);
                }
                if (handle == (IntPtr)~0)
                {
                    handle = IntPtr.Zero;
                }
                return handle;
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            public extern static void CloseHandle(IntPtr handle);

            [DllImport("kernel32.dll")]
            public static extern bool WriteFile(IntPtr fFile, 
                byte* lpBuffer,
                int nNumberOfBytesToWrite, 
                out int lpNumberOfBytesWritten, 
                OVERLAPPED* lpOverlapped);
        }

        public static ISet<string> FindAllComponentId()
        {
            ISet<string> s = NativeNetif.FindAllComponentId();
            return s;
        }

        private IntPtr OpenTunDev(string componentId)
        {
            string devName = $"\\\\.\\Global\\{componentId}.tap";
            return NativeNetif.OpenDrive(devName);
        }

        private void CloseTunDev(IntPtr handle)
        {
            if (handle != IntPtr.Zero)
            {
                NativeNetif.CloseHandle(handle);
            }
        }

        protected bool DeviceIoControl(uint commands, byte[] contents)
        {
            IntPtr hEvent = NativeNetif.CreateEvent(IntPtr.Zero, false, false, null);
            try
            {
                NativeNetif.OVERLAPPED overlapped = new NativeNetif.OVERLAPPED();
                overlapped.hEvent = hEvent;

                uint dw = 0;
                uint content_size = 0;
                if (contents == null)
                {
                    if (!NativeNetif.DeviceIoControl(this.Handle, commands,
                        contents, 0, contents, 0, ref dw, ref overlapped))
                    {
                        NativeNetif.WaitForSingleObject(hEvent, Timeout.Infinite);
                        return overlapped.Internal == NativeNetif.ERROR_SUCCESS;
                    }
                }
                else
                {
                    content_size = (uint)contents.Length;
                    if (!NativeNetif.DeviceIoControl(this.Handle, commands,
                        contents, content_size, contents, content_size, ref dw, ref overlapped))
                    {
                        NativeNetif.WaitForSingleObject(hEvent, Timeout.Infinite);
                        return overlapped.Internal == NativeNetif.ERROR_SUCCESS;
                    }
                }
                return true;
            }
            finally
            {
                if (hEvent != IntPtr.Zero)
                {
                    NativeNetif.CloseHandle(hEvent);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct IpNetifInfo
        {
            public uint address;
            public uint gateway;
            public uint subnetmask;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct DnsNetifInfo
        {
            public ushort reserved;
            public uint dns1;
            public uint dns2;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct DhcpNetifInfo
        {
            public uint gateway;
            public uint ip;
            public uint netmask;
        }

        private const uint METHOD_BUFFERED = 0;
        private const uint FILE_DEVICE_UNKNOWN = 0x00000022;
        private const uint FILE_ANY_ACCESS = 0;

        private static uint CTL_CODE(uint DeviceType, uint Function, uint Method, uint Access)
        {
            return ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method);
        }

        private static uint TAP_WIN_CONTROL_CODE(uint request, uint method)
        {
            return CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS);
        }

        public const int MTU = 1500;
        public const int MSS = 1400;

        private static readonly uint TAP_WIN_IOCTL_GET_MAC               = TAP_WIN_CONTROL_CODE (1, METHOD_BUFFERED);
        private static readonly uint TAP_WIN_IOCTL_GET_VERSION           = TAP_WIN_CONTROL_CODE (2, METHOD_BUFFERED);
        private static readonly uint TAP_WIN_IOCTL_GET_MTU               = TAP_WIN_CONTROL_CODE (3, METHOD_BUFFERED);
        private static readonly uint TAP_WIN_IOCTL_GET_INFO              = TAP_WIN_CONTROL_CODE (4, METHOD_BUFFERED);
        private static readonly uint TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT = TAP_WIN_CONTROL_CODE (5, METHOD_BUFFERED);
        private static readonly uint TAP_WIN_IOCTL_SET_MEDIA_STATUS      = TAP_WIN_CONTROL_CODE (6, METHOD_BUFFERED);
        private static readonly uint TAP_WIN_IOCTL_CONFIG_DHCP_MASQ      = TAP_WIN_CONTROL_CODE (7, METHOD_BUFFERED);
        private static readonly uint TAP_WIN_IOCTL_GET_LOG_LINE          = TAP_WIN_CONTROL_CODE (8, METHOD_BUFFERED);
        private static readonly uint TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT   = TAP_WIN_CONTROL_CODE (9, METHOD_BUFFERED);
        private static readonly uint TAP_WIN_IOCTL_CONFIG_TUN            = TAP_WIN_CONTROL_CODE(10, METHOD_BUFFERED);

        [DllImport("msvcrt.dll", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
        private static extern void system([MarshalAs(UnmanagedType.LPStr)]string command);

        private void StartNetifInformation(NetifConfiguration configuration)
        {
            byte[] dhcp = { 10, 0, 0, 0, 10, 0, 0, 1, 255, 255, 255, 0, 0, 1, 81, 128 };
            byte[] ip = { 10, 0, 0, 1, 10, 0, 0, 0, 255, 255, 255, 0 };
            byte[] dns = { 6, 8, 8, 8, 8, 8, 4, 4, 4, 4 };
            byte[] status = { 1, 0, 0, 0 };

            fixed (byte* pinned = dhcp)
            {
                DhcpNetifInfo* info = (DhcpNetifInfo*)pinned;
                info->ip = BitConverter.ToUInt32(configuration.Address.GetAddressBytes(), 0);
                info->gateway = BitConverter.ToUInt32(configuration.GatewayAddress.GetAddressBytes(), 0);
                info->netmask = BitConverter.ToUInt32(configuration.SubnetMask.GetAddressBytes(), 0);
            }
            fixed (byte* pinned = ip)
            {
                IpNetifInfo* info = (IpNetifInfo*)pinned;
                info->address = BitConverter.ToUInt32(configuration.Address.GetAddressBytes(), 0);
                info->gateway = BitConverter.ToUInt32(configuration.GatewayAddress.GetAddressBytes(), 0);
                info->subnetmask = BitConverter.ToUInt32(configuration.SubnetMask.GetAddressBytes(), 0);
            }
            fixed (byte* pinned = dns)
            {
                DnsNetifInfo* info = (DnsNetifInfo*)pinned;
                info->dns1 = BitConverter.ToUInt32(configuration.DnsAddress1.GetAddressBytes(), 0);
                info->dns2 = BitConverter.ToUInt32(configuration.DnsAddress2.GetAddressBytes(), 0);
            }

            DeviceIoControl(TAP_WIN_IOCTL_SET_MEDIA_STATUS, status); // netif-up
            DeviceIoControl(TAP_WIN_IOCTL_CONFIG_DHCP_MASQ, dhcp); // DHCP
            DeviceIoControl(TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT, dns); // DNS
            DeviceIoControl(TAP_WIN_IOCTL_CONFIG_TUN, ip); // IP mode 1

            string commands = $"netsh interface ip set address {this.Index} static {configuration.Address} {configuration.SubnetMask} ";
            system(commands);
        }

        private void ListenNetifLevel3Input(Action<byte[], int> callback)
        {
            NativeNetif.OVERLAPPED* overlapped = stackalloc NativeNetif.OVERLAPPED[1];
            byte[] buffer = new byte[MTU];
            while (0 == Interlocked.CompareExchange(ref this._disposed, 0, 0))
            {
                NativeNetif.memset(overlapped, 0, sizeof(NativeNetif.OVERLAPPED));
                int nNumberOfBytesToRead = 0;
                if (!NativeNetif.ReadFile(this.Handle, buffer, MTU, ref nNumberOfBytesToRead, ref *overlapped))
                {
                    if (!NativeNetif.GetOverlappedResult(this.Handle, overlapped, ref nNumberOfBytesToRead, true))
                    {
                        callback?.Invoke(buffer, ~0);
                        break;
                    }
                }
                callback?.Invoke(buffer, nNumberOfBytesToRead);
            }
        }

        private int SendNetifLevel3Output(byte[] buffer, int offset, int length)
        {
            if (offset < 0 | length < 0)
            {
                return ~0;
            }
            int num = (offset + length);
            if (buffer == null)
            {
                if (0 == num)
                {
                    return 0;
                }
                return ~0;
            }
            if (num > buffer.Length)
            {
                return ~0;
            }
            fixed (byte* pinned = buffer)
            {
                return SendNetifLevel3Output(pinned, offset, length);
            }
        }

        private int SendNetifLevel3Output(byte* buffer, int offset, int length)
        {
            if (offset < 0 || length < 0)
            {
                return ~0;
            }
            if (buffer == null)
            {
                int num = (offset + length);
                if (0 == num)
                {
                    return 0;
                }
                return ~0;
            }
            lock (this)
            {
                NativeNetif.OVERLAPPED* overlapped = stackalloc NativeNetif.OVERLAPPED[1];
                NativeNetif.memset(overlapped, 0, sizeof(NativeNetif.OVERLAPPED));
                if (!NativeNetif.WriteFile(this.Handle, &buffer[offset], length, out int lpNumberOfBytesWritten, overlapped))
                {
                    lpNumberOfBytesWritten = 0;
                    if (!NativeNetif.GetOverlappedResult(this.Handle, overlapped, ref lpNumberOfBytesWritten, true))
                    {
                        lpNumberOfBytesWritten = ~0;
                    }
                }
                return lpNumberOfBytesWritten;
            }
        }

        public static int GetAdapterIndex(string componentId)
        {
            if (string.IsNullOrEmpty(componentId))
            {
                return ~0;
            }
            foreach (var mbi2 in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (mbi2.Id == componentId)
                {
                    FieldInfo fi = mbi2.GetType().GetField("_index", BindingFlags.Instance | BindingFlags.NonPublic);
                    return Convert.ToInt32(fi.GetValue(mbi2));
                }
            }
            return ~0;
        }

        public static string GetAdapterName(string componentId)
        {
            if (string.IsNullOrEmpty(componentId))
            {
                return string.Empty;
            }
            foreach (var mbi2 in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (mbi2.Id == componentId)
                {
                    return mbi2.Name;
                }
            }
            return string.Empty;
        }

        public virtual void Listen(NetifConfiguration configuration)
        {
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));
            if (configuration.Address == null)
                throw new ArgumentNullException("The network interface device address is not allowed to be null");
            if (configuration.DnsAddress1 == null)
                throw new ArgumentNullException("The network interface device dns address 1 is not allowed to be null");
            if (configuration.DnsAddress2 == null)
                throw new ArgumentNullException("The network interface device dns address 2 is not allowed to be null");
            if (configuration.GatewayAddress == null)
                throw new ArgumentNullException("The network interface device gateway address is not allowed to be null");
            if (configuration.SubnetMask == null)
                throw new ArgumentNullException("The network interface device subnet mask is not allowed to be null");
            StartNetifInformation(configuration);
            ListenNetifLevel3Input((buffer, length) =>
            {
                IPFrame ip = IPv4.Parse(new BufferSegment(new BufferSegment(buffer, length).ToArray()));
                if (ip != null)
                {
                    IPv4.Input(ip);
                }
            });
        }

        public virtual void Output(BufferSegment buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }
            SendNetifLevel3Output(buffer.Buffer, buffer.Offset, buffer.Length);
        }
    }
}
#pragma warning restore IDE1006