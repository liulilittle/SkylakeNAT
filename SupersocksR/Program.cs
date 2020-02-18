namespace SupersocksR
{
    using System;
    using System.Net;
    using System.Text;
    using SupersocksR.SkylakeNAT;

    unsafe class Program
    {
        [MTAThread]
        static void Main(string[] args)
        {
            Console.Title = "SupersocksR *";
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = Encoding.UTF8;

            Router nat = new Router(IPAddress.Parse(args[0]), Convert.ToInt32(args[1]), args[2], Convert.ToInt32(args[3]));
            nat.Listen(int.MaxValue);
            Console.ReadKey(false);
        }
    }
}
