using Security;
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using UdpClient = NetCoreServer.UdpClient;

namespace NTPClient
{
    class NTPClient : UdpClient
    {
        public NTPClient(string address, int port) : base(address, port) { }

        public void DisconnectAndStop()
        {
            _stop = true;
            Disconnect();
            while (IsConnected)
                Thread.Yield();
        }

        protected override void OnConnected()
        {
            Console.WriteLine($"NTP UDP client connected a new session with Id {Id}");

            // Start receive datagrams
            ReceiveAsync();
        }

        protected override void OnDisconnected()
        {
            Console.WriteLine($"NTP UDP client disconnected a session with Id {Id}");

            // Wait for a while...
            Thread.Sleep(1000);

            // Try to connect again
            if (!_stop)
                Connect();
        }

        protected override void OnReceived(EndPoint endpoint, byte[] buffer, long offset, long size)
        {
            //Console.WriteLine("Incoming: " + Encoding.UTF8.GetString(buffer, (int)offset, (int)size));
            if(size == 32)
            {
                //int clientTime = BitConverter.ToInt32(buffer, (int)offset);
                //long serverTime = BitConverter.ToInt64(buffer, (int)offset + 4);
                //int rtt = (int)Program.watch.ElapsedMilliseconds - clientTime;
                //long diff = serverTime + ((long)rtt / 2) - DateTimeOffset.Now.ToUnixTimeMilliseconds();
                //Console.WriteLine($"Client time: {clientTime}, Server time: {serverTime}, RTT: {rtt}, diff: {diff}");

                string ntpAESkeyString = "dayLaAESKeyNtp!!";
                byte[] ntpAESkey = Encoding.UTF8.GetBytes(ntpAESkeyString);

                byte[] checkSum1 = AES.AES_Decrypt(buffer, (int)offset, 16, ntpAESkey, false);

                byte[] checkSum2 = MD5.MD5Hash(buffer, (int)offset + 16, 16);

                for (int i = 0; i < 16; i++)
                {
                    if (checkSum1[i] != checkSum2[i]) return;
                }

                byte[] decrypted = AES.AES_Decrypt(buffer, (int)offset + 16, 16, ntpAESkey, false);

                long curTimeOffset = BitConverter.ToInt64(decrypted, 0);

                var timestamp = DateTimeOffset.FromUnixTimeMilliseconds(curTimeOffset);

                Console.WriteLine(timestamp);
            }
            

            // Continue receive datagrams
            ReceiveAsync();
        }

        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"NTP UDP client caught an error with code {error}");
        }

        private bool _stop;
    }

    class Program
    {
        internal static Stopwatch watch;
        static void Main(string[] args)
        {
            // UDP server address
            string address = "127.0.0.1";
            //string address = "45.118.145.137";

            // UDP server port
            int port = 5000;

            Console.WriteLine($"UDP server address: {address}");
            Console.WriteLine($"UDP server port: {port}");

            // Create a new TCP chat client
            var client = new NTPClient(address, port);

            // Connect the client
            Console.Write("Client connecting...");
            client.Connect(); 
            Console.WriteLine("Done!");

            // Request NTP service
            watch = new Stopwatch();
            watch.Start();
            for (; ; )
            {
                //string line = Console.ReadLine();
                //if (string.IsNullOrEmpty(line))
                //    break;

                //// Disconnect the client
                //if (line == "1")
                //{

                //}

                //int curTime = (int)watch.ElapsedMilliseconds;
                //client.SendAsync(BitConverter.GetBytes(curTime));
                byte[] rdBuff = new byte[16];
                Random rd = new Random();
                rd.NextBytes(rdBuff);
                string ntpAESkeyString = "dayLaAESKeyNtp!!";
                byte[] ntpAESkey = Encoding.UTF8.GetBytes(ntpAESkeyString);
                rdBuff = AES.AES_Encrypt(rdBuff, 0, rdBuff.Length, ntpAESkey);

                byte[] checkSum = MD5.MD5Hash(rdBuff, 0, rdBuff.Length);

                checkSum = AES.AES_Encrypt(checkSum, 0, checkSum.Length, ntpAESkey);

                byte[] sendBuff = new byte[checkSum.Length + rdBuff.Length];

                System.Buffer.BlockCopy(checkSum, 0, sendBuff, 0, checkSum.Length);
                System.Buffer.BlockCopy(rdBuff, 0, sendBuff, checkSum.Length, rdBuff.Length);

                client.SendAsync(sendBuff);

                Thread.Sleep(1000);
            }

            //// Disconnect the client
            //Console.Write("Client disconnecting...");
            //client.DisconnectAndStop();
            //Console.WriteLine("Done!");
        }
    }
}
