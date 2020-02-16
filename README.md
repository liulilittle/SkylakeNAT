# SkylakeNAT
<br/>
Build SkylakeNAT-cli
<br/>
-------------------------------------------------------------------------------------
<br/>
DevTools choosable Visual C/C++ 2015, 2017, 2019...(IA32-x86)
<br/>
<br/>
vcpkg (https://github.com/Microsoft/vcpkg/)
<br/>
References:
<br/>
1、boost and boost::asio-x86
<br/>
2、openssl-x86
<br/>
3、TAP-Windows or TAP-Windows6 (openvpn)
<br/>

Build SupersocksR * (experiment)
<br/>
-------------------------------------------------------------------------------------
Nuget
<br/>
References: >= Microsoft .NET Framework 4.5、Microsoft Visual C++ 2010 x86 Runtime(CRT)
<br/>
1、Pcap.Net
<br/>
2、OpenSSL.Net
<br/>
3、WinPcap or WinPcap for Win10
<br/>

Route
-------------------------------------------------------------------------------------
1、The default gateway between the vNAT and the TAP device is 10.8.0.0
<br/>
2、If you need to run all (TCP/IP, ICMP, UDP/IP) protocol data through SkylakeNAT then 
you need to configure the following route (CMD/cli interface).
   <br/>
   > WIN + R (runas administrator) -> cmd
   <br/>
   <span> route add 0.0.0.0 mask 0.0.0.0 10.8.0.0</span>
   <br/>
   <span> route add 0.0.0.0 mask 128.0.0.0 10.8.0.0</span>
   <br/>
   <span> route add 128.0.0.0 mask 128.0.0.0 10.8.0.0</span>
   <br/>
   <br/>
   <span>WinAPI operation route can be referred to https://github.com/liulilittle/SkylakeNAT/blob/master/SupersocksR/Net/Routing/RouteTableManager.cs</span>
   <br/>
      <br/>
3、If you're only going to SkylakeNAT for an IP or IP segment, you can configure SkylakeNAT as follows
<br/>
   <span>&nbsp;&nbsp;&nbsp;&nbsp;1、route add 172.8.8.8 mask 255.255.255.255 10.8.0.0  (172.8.8.8 ~ 172.8.8.8)</span> <br/>
   <span>&nbsp;&nbsp;&nbsp;&nbsp;2、route add 198.18.0.0 mask 255.254.0.0 10.8.0.0  (198.18.0.0 ~ 198.19.255.255)</span> <br/>

Usage
-------------------------------------------------------------------------------------
Must run the program as Administrator
<br/>
Specify that the IP that the SupersocksR listens on must be an "Ethernet physical network card" (typically a RTL[Realtek] network card) that can access input or output traffic
<br/>
<br/>
1：SupersocksR 192.168.0.104 7521 yy523o! 25
<br/>
2：SkylakeNAT --server=192.168.0.104 --port=7521 --key=yy520o! --subtract=25 --max-concurrent=8
