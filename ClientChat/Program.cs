using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using TcpClient = NetCoreServer.TcpClient;

namespace ClientChat
{
    class ChatClient : TcpClient
    {
        public ChatClient(string address, int port) : base(address, port) { }

        public void DisconnectAndStop()
        {
            _stop = true;
            DisconnectAsync();
            while (IsConnected)
                Thread.Yield();
        }

        protected override void OnConnected()
        {
            //Console.WriteLine($"Chat TCP client connected a new session with Id {Id}");
        }

        protected override void OnDisconnected()
        {
            //Console.WriteLine($"Chat TCP client disconnected a session with Id {Id}");

            // Wait for a while...
            Thread.Sleep(1000);

            // Try to connect again
            if (!_stop)
                ConnectAsync();
        }

        protected override void OnReceived(byte[] buffer, long offset, long size)
        {
            //Console.WriteLine(Encoding.UTF8.GetString(buffer, (int)offset, (int)size));
            SendAsync(buffer, offset, size);
        }

        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"Chat TCP client caught an error with code {error}");
        }

        private bool _stop;
    }

    class Program
    {
        static void Main(string[] args)
        {
            // TCP server address
            string address = "127.0.0.1";

            // TCP server port
            int port = 5000;

            Console.WriteLine($"TCP server address: {address}");
            Console.WriteLine($"TCP server port: {port}");

            string numString = Console.ReadLine();
            int numInt = Int32.Parse(numString);

            List<ChatClient> listClient = new List<ChatClient>();
            // Create a new TCP chat client
            for(int i = 1000; i < 1000 + numInt; i++)
            {
                var client = new ChatClient(address, port);
                listClient.Add(client);
                client.ConnectAsync();
            }

            while (true) 
            {
                //Thread.Sleep(1000);
                //foreach(var dv in listClient)
                //{
                //    dv.SendAsync("Hello!!!");
                //}
            }
        }
    }
}
