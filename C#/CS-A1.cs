using System;
using System.Net;
using System.Linq;
using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using ConsoleTables;

// CS-A1
//
// Author:
//      @bigb0ss
// 
// Usage:
//      CS> execute-assembly cs-a1.exe
//
// Enumeration:
//      (1) Computer Name
//      (2) User Info
//      (3) Network Interface Info
//      (4) TCP Connections
//      (5) Process List

namespace csA1
{
    class Program
    {
        static void Main(string[] args)
        {
            banner();
            HostName();
            UserInfo();

            Console.Out.WriteLine("");
            NetworkInfo();
            DefaltGateway();

            Console.Out.WriteLine("");
            Console.Out.WriteLine("[+] Netstat");
            netstat();

            Console.Out.WriteLine("");
            Console.Out.WriteLine("[*] Querying Process list...");
            GetProcessInfo();

            Console.Out.WriteLine("");
            Console.Out.WriteLine("[+] Completed!");
            Console.ReadKey();
        }

        // Banner
        static void banner()
        {
            string banner = @"

     _____  _____             __     
    / ____|/ ____|       /\  /_ |   
   | |    | (___ ______ /  \  | |   
   | |     \___ |______/ /\ \ | | 
   | |____ ____) |    / ___\ \| |   
    \_____|_____/    /_/    \_|_|  
                     [bigb0ss]       

    v 1.0.0
            ";
            Console.Out.WriteLine(banner);
        }

        // Hostname
        static void HostName()
        {
            string hostName = Dns.GetHostName();
            Console.Out.WriteLine("[+] Hostname  : {0}",
                hostName);
            //Console.Out.WriteLine("   [+] Hostname: {0}", Environment.MachineName);
        }

        // Network Information
        static void NetworkInfo()
        {
            Console.Out.WriteLine("[+] Network Information: ");
            NetworkInterface[] Interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface i in Interfaces)
            {
                if (i.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                Console.WriteLine("- Interface: {0}", i.Description);
                UnicastIPAddressInformationCollection UnicastIPInfoCol = i.GetIPProperties().UnicastAddresses;
                foreach (UnicastIPAddressInformation UnicatIPInfo in UnicastIPInfoCol)
                {
                    Console.WriteLine("\t[+] IP Address : {0}", UnicatIPInfo.Address);
                    Console.WriteLine("\t[+] Subnet Mask: {0}", UnicatIPInfo.IPv4Mask);
                }
            }
        }

        static void DefaltGateway()
        {
            var defaultGateway =
            from nics in NetworkInterface.GetAllNetworkInterfaces()
            from props in nics.GetIPProperties().GatewayAddresses
            where nics.OperationalStatus == OperationalStatus.Up
            select props.Address.ToString();

            Console.WriteLine("- Default Gateway: {0}", defaultGateway.First());
        }

        // User Info
        static void UserInfo()
        {
            Console.Out.WriteLine("[+] User_Info : {0}\\{1}",
                Environment.UserDomainName,
                Environment.UserName);
        }

        // Netstat Information
        static void netstat()
        {
            IPGlobalProperties ipProperties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] endPoints = ipProperties.GetActiveTcpListeners();
            TcpConnectionInformation[] tcpConnections = ipProperties.GetActiveTcpConnections();

            var table = new ConsoleTable("Local Address", "Foreign Address", "State");

            foreach (TcpConnectionInformation info in tcpConnections)
            {
                string local = info.LocalEndPoint.Address.ToString() + ":" + info.LocalEndPoint.Port.ToString();
                string remote = info.RemoteEndPoint.Address.ToString() + ":" + info.RemoteEndPoint.Port.ToString();
                string state = info.State.ToString();
                // Only Established Connections
                if (state.Contains("Established") == true)
                {
                    table.AddRow(local, remote, state);
                }
                // For Every Connection
                //table.AddRow(local, remote, state);
            }
            table.Write(Format.Alternative);
        }

        // Get Process Info
        static void GetProcessInfo()
        {
            var table = new ConsoleTable("Process", "PID", "Owner");

            foreach (var process in Process.GetProcesses())
            {
                string name = process.ProcessName;
                int processId = process.Id;
                string owner = GetProcessOwner(processId);
                table.AddRow(name, processId, owner);
            }
            table.Write(Format.Alternative);

        }

        // Get Process Owner
        static string GetProcessOwner(int processId)
        {
            string query = "Select * From Win32_Process Where ProcessID = " + processId;
            ManagementObjectSearcher moSearcher = new ManagementObjectSearcher(query);
            ManagementObjectCollection moCollection = moSearcher.Get();

            foreach (ManagementObject mo in moCollection)
            {
                string[] args = new string[] { string.Empty };
                int returnVal = Convert.ToInt32(mo.InvokeMethod("GetOwner", args));
                if (returnVal == 0)
                    return args[0];
            }
            return "Null";
        }
    }
}
