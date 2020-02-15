namespace SupersocksR.Tun2Socks
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Sockets;
    using System.Text;
    using System.Text.RegularExpressions;
    using SupersocksR.Net.Tools;

    public class PAC
    {
        private IEnumerable<IPAddressRange> m_aoAddressRangeTable = null;

        public virtual void Refresh()
        {
            this.DownloadPAC((success, addressRangeTable) =>
            {
                if (addressRangeTable != null)
                {
                    this.m_aoAddressRangeTable = addressRangeTable;
                }
            });
        }

        public virtual bool IsReady() => this.m_aoAddressRangeTable != null;

        public virtual bool IsNotAllowAgent(IPAddress address)
        {
            if (address == null)
            {
                return false;
            }

            if (address.AddressFamily != AddressFamily.InterNetwork)
            {
                return false;
            }

            var aoAddressRangeTable = this.m_aoAddressRangeTable;
            if (aoAddressRangeTable == null)
            {
                return false;
            }

            foreach (IPAddressRange poAddressRange in aoAddressRangeTable)
            {
                if (poAddressRange.Contains(address))
                {
                    return true;
                }
            }

            return false;
        }

        public virtual void DownloadPAC(Action<bool, IEnumerable<IPAddressRange>> success)
        {
            DownloadPAC("http://ip.bczs.net/country/CN", (completed, contents) =>
            {
                if (success != null)
                {
                    var addresses = ResolvePACString(contents);
                    success(completed, addresses);
                }
            });
        }

        public virtual void DownloadPAC(string url, Action<bool, string> success)
        {
            WebClient wc = new WebClient
            {
                Encoding = Encoding.UTF8
            };
            try
            {
                wc.DownloadStringCompleted += delegate (object sender, DownloadStringCompletedEventArgs e)
                {
                    wc.Dispose();
                    if (e == null || e.Error != null || e.Cancelled || string.IsNullOrEmpty(e.Result))
                    {
                        success?.Invoke(false, string.Empty);
                    }
                    else
                    {
                        success?.Invoke(true, e.Result);
                    }
                };
                wc.DownloadStringAsync(new Uri(url));
            }
            catch (Exception)
            {
                wc.Dispose();
                success?.Invoke(false, string.Empty);
            }
        }

        private string inet_address(string s)
        {
            if (string.IsNullOrEmpty(s))
            {
                return string.Empty;
            }

            var m = Regex.Match(s, @"([0-9]{1,3}[\.][0-9]{1,3}[\.][0-9]{1,3}[\.][0-9]{1,3})", RegexOptions.IgnoreCase | RegexOptions.Multiline);
            if (!m.Success)
            {
                return string.Empty;
            }

            if (m.Groups.Count < 2)
            {
                return string.Empty;
            }

            return m.Groups[1].Value;
        }

        public virtual IEnumerable<IPAddressRange> ResolvePACString(string pac)
        {
            ISet<IPAddressRange> addresses = new HashSet<IPAddressRange>();
            if (string.IsNullOrEmpty(pac))
            {
                return addresses;
            }

            var matches = Regex.Matches(pac, @"<a[\s\S]+?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[\s\S]+?<td[\s\S]+?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            foreach (Match match in matches)
            {
                if (match.Groups.Count < 2)
                {
                    continue;
                }

                string start_addresses = inet_address(match.Groups[1].Value);
                string end_addresses = string.Empty;
                if (match.Groups.Count > 2)
                {
                    end_addresses = inet_address(match.Groups[2].Value);
                }

                if (string.IsNullOrEmpty(start_addresses))
                {
                    start_addresses = end_addresses;
                }

                if (string.IsNullOrEmpty(end_addresses))
                {
                    end_addresses = start_addresses;
                }

                if (string.IsNullOrEmpty(start_addresses))
                {
                    continue;
                }

                try
                {
                    string ipRangeString = $"{start_addresses}-{end_addresses}";
                    {
                        if (!IPAddressRange.TryParse(ipRangeString, out IPAddressRange addressesRange))
                        {
                            continue;
                        }

                        if (addressesRange == null)
                        {
                            continue;
                        }

                        addresses.Add(addressesRange);
                    }
                }
                catch (Exception)
                {
                    continue;
                }
            }

            return addresses;
        }
    }
}
