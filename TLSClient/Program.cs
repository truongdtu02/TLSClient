using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Serilog;
using System;
using System.IO;
using Security;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Timers;
using System.Threading;
using System.Text;
using TcpClient = NetCoreServer.TcpClient;
using System.Net.Sockets;

namespace TLSClient
{
    class Program
    {
        internal static IHost host { get; private set; }

        static void Main(string[] args)
        {
            StartUp();

            //DeviceServer deviceServer = host.Services.GetRequiredService<DeviceServer>();
            //deviceServer.Run();

            // TCP server address
            string address = "127.0.0.1";
            //string address = "45.118.145.137";

            int port = 5000;

            Console.WriteLine($"TCP server address, port : {address}, {port}");

            Console.Write("Num of clients: ");
            string tmp = Console.ReadLine();
            int num = Int32.Parse(tmp);
            Console.WriteLine("Num of clients: {0}", num);

            Console.Write("Thread sleep: ");
            tmp = Console.ReadLine();
            int threadsleep = Int32.Parse(tmp);
            Console.WriteLine("Thread sleep: {0}", threadsleep);

            for (int i = 1000; i < 1000 + num; i++)
            {
                // Create a new TCP chat client
                var client = new TLSClient(address, port, host.Services.GetRequiredService<ILogger<TLSClient>>());
                client.ConfigParam(i.ToString(), 10000);
                // Connect the client
                //Console.Write("Client connecting...");
                client.ConnectAsync();
                //Console.WriteLine("Done!");

                Thread.Sleep(threadsleep);
            }

            // Perform text input
            for (; ; )
            {
                //// Disconnect the client
                //if (line == "!")
                //{
                //    Console.Write("Client disconnecting...");
                //    client.DisconnectAsync();
                //    Console.WriteLine("Done!");
                //    continue;
                //}

                //// Send the entered text to the chat server
                //client.SendAsync(line);
            }

            // Disconnect the client
            Console.Write("Client disconnecting...");
            Console.WriteLine("Done!");
        }

        static void BuildConfig(IConfigurationBuilder builder)
        {
            builder.SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENRT") ?? "Production"}.json", optional: true)
                .AddEnvironmentVariables();
        }
        static void StartUp()
        {
            //Console.WriteLine("Hello World!");
            var builder = new ConfigurationBuilder();
            BuildConfig(builder);
            var configurationroot = builder.Build();

            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(builder.Build())
                .Enrich.FromLogContext()
                .WriteTo.Console()
                .WriteTo.File("log.txt")
                .CreateLogger();

            Log.Logger.Information("Application Starting");

            host = Host.CreateDefaultBuilder()
                .ConfigureServices((context, services) =>
                {
                    ////register option to DI
                    ////services.Configure<TruyenthanhDatabaseSettings>(
                    ////    Configuration.GetSection(nameof(TruyenthanhDatabaseSettings))); 
                    //services.Configure<TruyenthanhDatabaseSettings>(
                    //      configurationroot.GetSection(nameof(TruyenthanhDatabaseSettings)));

                    ////register DI by factory
                    //services.AddSingleton<ITruyenthanhDatabaseSettings>(sp =>
                    //    sp.GetRequiredService<IOptions<TruyenthanhDatabaseSettings>>().Value);
                    ////sp.GetRequiredService<IOptions<TruyenthanhDatabaseSettings>>().Value:
                    //// get instance of object option is registered above
                    //services.AddSingleton<DeviceServer>(sp => {
                    //    DeviceServer deviceServer = new DeviceServer(IPAddress.Any, configurationroot.GetSection("DeviceServer").GetValue<int>("DevicePort"),
                    //        sp.GetRequiredService<ILogger<DeviceServer>>());
                    //    return deviceServer;
                    //});
                    //services.AddTransient<DeviceSession>(sp =>
                    //{
                    //    DeviceSession deviceSession = new DeviceSession(
                    //        sp.GetRequiredService<DeviceServer>(),
                    //        sp.GetRequiredService<ILogger<DeviceSession>>());
                    //    return deviceSession;
                    //});

                    //services.AddTransient<TLSSession>(sp =>
                    //{
                    //    TLSSession tlsSession = new TLSSession(
                    //        sp.GetRequiredService<DeviceServer>(),
                    //        sp.GetRequiredService<ILogger<TLSSession>>());
                    //    return tlsSession;
                    //});

                })
                .UseSerilog()
                .Build();
        }
    }
}
