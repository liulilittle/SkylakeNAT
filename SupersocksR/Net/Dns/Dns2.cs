namespace SupersocksR.Net.Dns
{
    using System;
    using System.Collections.Concurrent;
    using System.Net;
    using SupersocksR.Net.Dns.OpenDNS;

    public class Dns2
    {
        private static ConcurrentDictionary<string, IPAddress> m_hosts = new ConcurrentDictionary<string, IPAddress>();

        public static IPEndPoint[] DefaultServers = new IPEndPoint[] // 默认的解析服务器群组
        {
            new IPEndPoint(IPAddress.Parse("208.67.222.222"), 53), // Open DNS
            new IPEndPoint(IPAddress.Parse("208.67.220.220"), 53), // Open DNS
            new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53), // Google
            new IPEndPoint(IPAddress.Parse("8.8.4.4"), 53), // Google
        };

        public static IPAddress Resolve(string hostname)
        {
            return Dns2.Resolve(hostname, DefaultServers);
        }

        private static IPAddress ResolveInsert(string hostname, Func<IPAddress> dns)
        {
            if (string.IsNullOrEmpty(hostname))
                return null;
            IPAddress ip;
            if (m_hosts.TryGetValue(hostname, out ip))
                return ip;
            ip = dns();
            if (ip != null)
                m_hosts.TryAdd(hostname, ip);
            return ip;
        }

        public static IPAddress Resolve(string hostname, params IPEndPoint[] servers)
        {
            return Dns2.ResolveInsert(hostname, () => Dns2.ResolveAddress(hostname, servers, false));
        }

        private static IPAddress ResolveAddress(string hostname, IPEndPoint[] servers, bool ipv6)
        {
            try
            {
                Types[] types = ipv6 ? new Types[] { Types.AAAA, Types.A } : new Types[] { Types.A, Types.AAAA };
                for (int i = 0; i < types.Length; ++i)
                {
                    DnsQuery dns = new DnsQuery(hostname, types[i]);
                    dns.RecursionDesired = true;
                    dns.Servers.AddRange(servers);
                    if (dns.Send())
                    {
                        int len = dns.Response.Answers.Count;
                        if (len > 0)
                        {
                            for (int j = 0; j < len; ++j)
                            {
                                if (((ResourceRecord)dns.Response.Answers[j]).Type != types[i])
                                    continue;
                                return ((Address)dns.Response.Answers[j]).IP;
                            }
                        }
                    }
                }
            }
            catch
            {

            }
            try 
            {
                IPAddress[] ips = System.Net.Dns.GetHostAddresses(hostname);
                if (ips.Length <= 0)
                    return null;
                return ips[0];
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
