using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

class NetworkScanner
{
    static void GetNetworkAddresses(string ipAddress, string subnetMask, out string[] startAddress, out string[] finalAddress)
    {
        string[] ipAddressParts = ipAddress.Split('.');
        string[] subnetMaskParts = subnetMask.Split('.');
        startAddress = new string[ipAddressParts.Length];
        finalAddress = new string[ipAddressParts.Length];
        for (int i = 0; i < ipAddressParts.Length; i++)
            startAddress[i] = (byte.Parse(ipAddressParts[i]) & byte.Parse(subnetMaskParts[i])).ToString();
        for (int i = 0; i < finalAddress.Length; i++)
        {
            string maskBinaryRepresentation = Convert.ToString(byte.Parse(subnetMaskParts[i]), 2).PadLeft(8, '0');
            char[] invertedBinaryChars = maskBinaryRepresentation.Select(bit => bit == '0' ? '1' : '0').ToArray();
            string maskBinaryRepresentationStr = new string(invertedBinaryChars);
            string startAddressBinaryRepresentation = Convert.ToString(byte.Parse(startAddress[i]), 2).PadLeft(8, '0');
            char[] result = new char[maskBinaryRepresentationStr.Length];
            for (int j = 0; j < maskBinaryRepresentationStr.Length; j++)
                result[j] = ((maskBinaryRepresentationStr[j] == '1' || startAddressBinaryRepresentation[j] == '1') ? '1' : '0');
            finalAddress[i] = new string(result);
            finalAddress[i] = Convert.ToInt32(finalAddress[i], 2).ToString();
        }
    }
    static bool PingHost(string ip)
    {
        using (Ping ping = new Ping())
        {
            try
            {
                PingReply reply = ping.Send(ip);
                return reply.Status == IPStatus.Success;
            }
            catch (PingException)
            {
                return false;
            }
        }
    }
    static class NativeMethods
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(int destIP, int srcIP, byte[] pMacAddr, ref uint phyAddrLen);
    }
    private static string? GetName(string ipAddress)
    {
        IPHostEntry hostEntry;
        try
        {
            hostEntry = Dns.GetHostEntry(ipAddress);
        }
        catch (SocketException)
        {
            return "Unknown";
        }
        return (hostEntry.HostName == null) ? "Unknown" : hostEntry.HostName;
    }
    static string? GetMac(string ipAddress)
    {
        try
        {
            byte[] macAddr = new byte[6];
            uint macAddrLen = (uint)macAddr.Length;
            int dest = BitConverter.ToInt32(IPAddress.Parse(ipAddress).GetAddressBytes(), 0);
            return NativeMethods.SendARP(dest, 0, macAddr, ref macAddrLen) == 0 ? string.Join(":", macAddr.Select(x => x.ToString("X2"))): null;
        }
        catch
        {
            return null;
        }
    }
    public static void CalculateThread(string ip)
    {
        string mac = "";
        Thread macThread = new Thread(() =>
        {
            mac = GetMac(ip);
        });
        macThread.Start();
        string name = GetName(ip);
        if (mac != null && !mac.Equals("00:00:00:00:00:00"))
        {
            Console.Write($"IP: {ip},");
            Console.Write($" MAC: {mac},");
            Console.WriteLine($" Device: {name}");
        }
    }
    static void PingAndGetMacAddresses(string[] startIp, string[] endIp)
    {
        List<Task> tasks = new List<Task>();
        int startRange = int.Parse(startIp[3]);
        int endRange = int.Parse(endIp[3]);
        int rangeSize = (endRange - startRange + 1) / 50;
        for (int j = 0; j < 50; j++)
        {
            int rangeStart = startRange + j * rangeSize;
            int rangeEnd = j == 99 ? endRange : rangeStart + rangeSize - 1; 
            Task task = Task.Run(() =>
            {
                for (int i = rangeStart; i <= rangeEnd; i++)
                {
                    string ip = $"{startIp[0]}.{startIp[1]}.{startIp[2]}.{i}";
                    //if (PingHost(ip))
                        CalculateThread(ip);
                }
            });
            tasks.Add(task);
        }
        Task.WaitAll(tasks.ToArray());
    }
    static void ScanLocalNetwork()
    {
        NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
        foreach (NetworkInterface adapter in interfaces)
        {
            if ((adapter.OperationalStatus == OperationalStatus.Up) && (!adapter.Description.ToLower().Contains("virtual")))
            {
                UnicastIPAddressInformationCollection ipAddresses = adapter.GetIPProperties().UnicastAddresses;
                foreach (UnicastIPAddressInformation ipAddress in ipAddresses)
                {
                    if (ipAddress.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        string[] startAddress;
                        string[] finalAddress;
                        GetNetworkAddresses(ipAddress.Address.ToString(), ipAddress.IPv4Mask.ToString(), out startAddress, out finalAddress);
                        PingAndGetMacAddresses(startAddress, finalAddress);
                    }
                }
            }
        }
    }
    static void Main()
    {
        ScanLocalNetwork();
        Console.WriteLine("That's all");
    }
}