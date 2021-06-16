using OpenRPA.Interfaces.entity;
using OpenRPA.Net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenRPA.RDService
{
    using FlaUI.UIA3.Patterns;
    using Microsoft.Win32;
    using OpenRPA.Interfaces;
    using System.IO;
    using System.IO.Pipes;
    using System.Net;
    using System.Security;
    using System.Threading;

    class Program
    {
        public const int StartupWaitSeconds = 0;
        public const string ServiceName = "OpenRPA";
        private static ServiceManager manager = new ServiceManager(ServiceName);
        private static ServiceManager Monitormanager = new ServiceManager("OpenRPAMon");
        public static bool isService = false;
        private static Tracing tracing = null;
        private static System.Timers.Timer reloadTimer = null;
        public static bool isWindowsLocked = false;
        public static string launcherCommand = "None";
        private void GetSessions()
        {
            IntPtr server = IntPtr.Zero;
            List<string> ret = new List<string>();
            try
            {
                server = NativeMethods.WTSOpenServer(".");
                IntPtr ppSessionInfo = IntPtr.Zero;
                int count = 0;
                int retval = NativeMethods.WTSEnumerateSessions(server, 0, 1, ref ppSessionInfo, ref count);
                int dataSize = System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.WTS_SESSION_INFO));
                long current = (int)ppSessionInfo;
                if (retval != 0)
                {
                    for (int i = 0; i < count; i++)
                    {
                        NativeMethods.WTS_SESSION_INFO si = (NativeMethods.WTS_SESSION_INFO)System.Runtime.InteropServices.Marshal.PtrToStructure((System.IntPtr)current, typeof(NativeMethods.WTS_SESSION_INFO));
                        current += dataSize;
                        ret.Add(si.SessionID + " " + si.State + " " + si.pWinStationName);
                    }
                    NativeMethods.WTSFreeMemory(ppSessionInfo);
                }
            }
            catch (Exception ex)
            {
                Log.Information(ex.ToString());
            }
            finally
            {
                try
                {
                    NativeMethods.WTSCloseServer(server);
                }
                catch (Exception)
                {
                }
            }
        }
        private static string logpath = "";
        private static void log(string message)
        {
            try
            {
                Log.Information(message);
                DateTime dt = DateTime.Now;
                var _msg = string.Format(@"[{0:HH\:mm\:ss\.fff}] {1}", dt, message);
                System.IO.File.AppendAllText(System.IO.Path.Combine(logpath, "log_rdservice.txt"), _msg + Environment.NewLine);
            }
            catch (Exception ex)
            {
                Log.Information(ex.Message);
            }
        }
        private static string[] args;
        static void Main(string[] args)
        {
            try
            {
                Program.args = args;
                var asm = System.Reflection.Assembly.GetEntryAssembly();
                var filepath = asm.CodeBase.Replace("file:///", "");
                logpath = System.IO.Path.GetDirectoryName(filepath);
                Log.Information("Main: logpath is " + logpath);

                //UIThread = new Thread(() =>
                //{
                //    System.Windows.Threading.Dispatcher.CurrentDispatcher.BeginInvoke(new Action(() =>
                //    {
                //        AutomationHelper.syncContext = System.Threading.SynchronizationContext.Current;
                //    }));

                //    System.Windows.Threading.Dispatcher.Run();
                //});

                //UIThread.SetApartmentState(ApartmentState.STA);
                //UIThread.Start();



                Log.Information("main 1");
                log("GetParentProcessId");
                Log.Information("main 200");
                var parentProcess = NativeMethods.GetParentProcessId();
                log("Check parentProcess");
                Log.Information("main 5");
                isService = (parentProcess.ProcessName.ToLower() == "services");
                Log.Information("****** isService: " + isService);
                SystemEvents.SessionSwitch += SystemEvents_SessionSwitch;
                if (isService)
                {
                    log("ServiceBase.Run");
                    System.ServiceProcess.ServiceBase.Run(new MyServiceBase(ServiceName, DoWork));
                    isWindowsLocked = true;
                }
                else
                {
                    isWindowsLocked = false;
                    log("DoWork");
                    DoWork();
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex.ToString());
            }
        }
        static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs args)
        {
            Exception ex = (Exception)args.ExceptionObject;
            Log.Error(ex, "");
            Log.Error("MyHandler caught : " + ex.Message);
            Log.Error("Runtime terminating: {0}", (args.IsTerminating).ToString());
        }
        private static void WebSocketClient_OnQueueMessage(Interfaces.IQueueMessage message, Interfaces.QueueMessageEventArgs e)
        {
            Log.Debug("WebSocketClient_OnQueueMessage");
        }
        private static bool autoReconnect = true;
        private async static void WebSocketClient_OnClose(string reason)
        {
            Log.Information("Disconnected " + reason);
            await Task.Delay(1000);
            if (autoReconnect)
            {
                autoReconnect = false;
                try
                {
                    global.webSocketClient.OnOpen -= WebSocketClient_OnOpen;
                    global.webSocketClient.OnClose -= WebSocketClient_OnClose;
                    global.webSocketClient.OnQueueMessage -= WebSocketClient_OnQueueMessage;
                    global.webSocketClient = null;

                    global.webSocketClient = new WebSocketClient(PluginConfig.wsurl);
                    global.webSocketClient.OnOpen += WebSocketClient_OnOpen;
                    global.webSocketClient.OnClose += WebSocketClient_OnClose;
                    global.webSocketClient.OnQueueMessage += WebSocketClient_OnQueueMessage;
                    await global.webSocketClient.Connect();
                    autoReconnect = true;
                }
                catch (Exception ex)
                {
                    Log.Error(ex.ToString());
                }
            }
        }
        public static byte[] Base64Decode(string base64EncodedData)
        {
            return System.Convert.FromBase64String(base64EncodedData);
        }
        public static string Base64Encode(byte[] bytes)
        {
            return System.Convert.ToBase64String(bytes);
        }

        public static void SystemEvents_SessionSwitch(object sender, SessionSwitchEventArgs e)
        {
            if (e.Reason == SessionSwitchReason.SessionLock)
            {
                Log.Information("The Desktop is locked...");
                isWindowsLocked = true;
            }

            if (e.Reason == SessionSwitchReason.SessionUnlock)
            {
                Log.Information("The Desktop is unlock...");
                isWindowsLocked = false;
            }
        }
        private static async void WebSocketClient_OnOpen()
        {
            try
            {
                var hostname = NativeMethods.GetHostName().ToLower();
                Log.Information("WebSocketClient_OnOpen: " + hostname);
                /*TokenUser user = null;
                while (user == null)
                {
                    if (!string.IsNullOrEmpty(PluginConfig.tempjwt))
                    {
                        user = await global.webSocketClient.Signin(PluginConfig.tempjwt, "RDService", System.Reflection.Assembly.GetEntryAssembly().GetName().Version.ToString()); 
                        if (user != null)
                        {
                            if (isService)
                            {
                                PluginConfig.jwt = Base64Encode(PluginConfig.ProtectString(PluginConfig.tempjwt));
                                PluginConfig.tempjwt = null;
                                PluginConfig.Save();
                            }
                            Log.Information("Signed in as " + user.username);
                        }
                    }
                    else if (PluginConfig.jwt != null && PluginConfig.jwt.Length > 0)
                    {
                        //user = await global.webSocketClient.Signin(PluginConfig.UnprotectString(Base64Decode(PluginConfig.jwt)), "RDService", System.Reflection.Assembly.GetEntryAssembly().GetName().Version.ToString());
                        SecureString s_password = new NetworkCredential("", "1").SecurePassword;
                        user = await global.webSocketClient.Signin("BonBon", s_password, "RDService", System.Reflection.Assembly.GetEntryAssembly().GetName().Version.ToString());
                        if (user != null)
                        {
                            Log.Information("Signed in as " + user.username);
                        }
                    }
                    else
                    {
                        Log.Error("Missing jwt from config, close down");
                        _ = global.webSocketClient.Close();
                        if (isService) await manager.StopService();
                        if (!isService) Environment.Exit(0);
                        return;
                    }
                }
                string computername = NativeMethods.GetHostName().ToLower();
                string computerfqdn = NativeMethods.GetFQDN().ToLower();
                Log.Information("WebSocketClient_OnOpen: "  + computername + " : " + computerfqdn);
                var servers = await global.webSocketClient.Query<unattendedserver>("openrpa", "{'_type':'unattendedserver', 'computername':'" + computername + "', 'computerfqdn':'" + computerfqdn + "'}");
                Log.Information("WebSocketClient_OnOpen 1");
                unattendedserver server;// = servers.FirstOrDefault();
                if (servers.Length == 0)
                {
                    Log.Information("Adding new unattendedserver for " + computerfqdn);
                    server = new unattendedserver() { computername = computername, computerfqdn = computerfqdn, name = computerfqdn, enabled = true };
                    Log.Information("1.Adding new unattendedserver for " + computerfqdn);
                    if(global.webSocketClient == null)
                    {
                        Log.Information("webSocketClient is null " + computerfqdn);
                        return;
                    }
                    server = await global.webSocketClient.InsertOne("openrpa", 1, false, server);
                    Log.Information("2.Adding new unattendedserver for " + computerfqdn);
                }*/
                //var clients = await global.webSocketClient.Query<unattendedclient>("openrpa", "{'_type':'unattendedclient', 'computername':'" + computername + "', 'computerfqdn':'" + computerfqdn + "'}");
                //foreach (var c in clients) sessions.Add(new RobotUserSession(c));
                // Log.Information("Loaded " + sessions.Count + " sessions");
                // Create listener for robots to connect too
                // Clear all sessions
                sessions.Clear();
                //sessions.Add(new RobotUserSession(null));
                if (pipe==null)
                {
                    Log.Information("Create listener for robots to connect...");
                    PipeSecurity ps = new PipeSecurity();
                    ps.AddAccessRule(new PipeAccessRule("Users", PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, System.Security.AccessControl.AccessControlType.Allow));
                    ps.AddAccessRule(new PipeAccessRule("CREATOR OWNER", PipeAccessRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
                    ps.AddAccessRule(new PipeAccessRule("SYSTEM", PipeAccessRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
                    pipe = new OpenRPA.NamedPipeWrapper.NamedPipeServer<RPAMessage>("openrpa_service", ps);
                    pipe.ClientConnected += Pipe_ClientConnected;
                    pipe.ClientMessage += Pipe_ClientMessage;
                    pipe.Start();
                }

                Log.Information("reloadinterval is " + PluginConfig.reloadinterval.TotalSeconds + " seconds");
                ReadConfig();
                if (reloadTimer==null)
                {
                    //reloadTimer = new System.Timers.Timer(PluginConfig.reloadinterval.TotalMilliseconds);
                    reloadTimer = new System.Timers.Timer(10000);
                    reloadTimer.Elapsed += async (o,e) =>
                    {
                        reloadTimer.Stop();
                        try
                        {
                            await ReloadConfig();
                        }
                        catch (Exception ex)
                        {
                            Log.Error(ex.ToString());
                        }
                        reloadTimer.Start();
                    };
                }
                reloadTimer.Start();
            }
            catch (Exception ex)
            {
                Log.Error(ex.ToString());
            }
        }
        // Read the config file and save to processIds list.
        private static bool ReadConfig()
        {
            string line;
            var asm = System.Reflection.Assembly.GetEntryAssembly();
            var filepath = asm.CodeBase.Replace("file:///", "");
            var configpath = System.IO.Path.GetDirectoryName(filepath);
            System.IO.StreamReader file =
                new System.IO.StreamReader(System.IO.Path.Combine(configpath, "config.dat"));
            if (file != null)
            {
                while ((line = file.ReadLine()) != null)
                {
                    if(!string.IsNullOrWhiteSpace(line))
                        processIds.Add(line);
                }
                file.Close();
            }
            return false;
        }

        private static bool disabledmessageshown = false;
        private static async Task ReloadConfig()
        {
            try
            {
                Log.Information("ReloadConfig.....");
#if true

                Log.Information("sever is " + PluginConfig.serveruri);
                if(string.IsNullOrWhiteSpace(PluginConfig.serveruri))
                {
                    Log.Information("server API is empty.");
                    return;
                }
                if(processIds.Count <= 0)
                {
                    Log.Information("It has not any process id");
                    return;
                }
                // read config for each process id from servser
                foreach(var process_id in processIds)
                {
                    var httpWebRequest = (HttpWebRequest)WebRequest.Create(PluginConfig.serveruri);
                    httpWebRequest.ContentType = "application/json";
                    httpWebRequest.Method = "POST";
                    Log.Information("Query the action for " + process_id);

                    using (var streamWriter = new StreamWriter(httpWebRequest.GetRequestStream()))
                    {
                        string json = "{\"id_proceso\":\"" + process_id + "\"}";

                        streamWriter.Write(json);
                    }

                    var httpResponse = (HttpWebResponse)httpWebRequest.GetResponse();
                    using (var streamReader = new StreamReader(httpResponse.GetResponseStream()))
                    {
                        var result = streamReader.ReadToEnd();
                        Log.Information("result for " + process_id + " is " + result);
                        if (result == "\"Play\"" || result == "\"Stop\"") // start RD session and Launcher-RPA
                        {
                            if(isWindowsLocked)
                            {
                                var session = sessions.Where(x => x.client.processid == process_id).FirstOrDefault();
                                if (session == null)
                                {
                                    Log.Information("Start session for process " + process_id);
                                    unattendedclient client = new unattendedclient();
                                    client.processid = process_id;
                                    client.windowsusername = PluginConfig.windowsusername;
                                    client.windowspassword = PluginConfig.windowspassword;
                                    client.enabled = true;
                                    sessions.Add(new RobotUserSession(client));

                                    // waiting until login success
                                }
                            }
                            // Start Launcher-RPA.exe with process_id
                            var asm = System.Reflection.Assembly.GetEntryAssembly();
                            var filepath = asm.CodeBase.Replace("file:///", "");
                            var exepath = System.IO.Path.GetDirectoryName(filepath);
                            var command = " Play";
                            if (result == "\"Play\"")
                            {
                                command = " Play";
                                launcherCommand = "Play";
                            }
                            else
                            {
                                command = " Stop";
                                launcherCommand = "Stop";
                            }
                            if (System.IO.File.Exists(System.IO.Path.Combine(exepath, "Launcher-RPA.exe")))
                            {
                                Log.Information("Sending to launcher: " + System.IO.Path.Combine(exepath, "Launcher-RPA.exe"));
                                Log.Information("with arguments: " + process_id + command + "/");
                                var process = System.Diagnostics.Process.Start(System.IO.Path.Combine(exepath, "Launcher-RPA.exe"), process_id + command);
                                //process.WaitForExit();
                            } else
                            {
                                Log.Information("File Launcher-RPA.exe is not existed at " + exepath);
                            }
                        } 
                        /*else if (result.Contains("Stop")) // Stop session for RD service
                        {
                            foreach(var session in sessions)
                            {
                                if(session.client.processid == process_id)
                                {
                                    Log.Information("Close session for process " + process_id);
                                    sessions.Remove(session);
                                    session.Dispose();

                                    var asm = System.Reflection.Assembly.GetEntryAssembly();
                                    var filepath = asm.CodeBase.Replace("file:///", "");
                                    var exepath = System.IO.Path.GetDirectoryName(filepath);
                                    if (System.IO.File.Exists(System.IO.Path.Combine(exepath, "Launcher-RPA.exe")))
                                    {
                                        var process = System.Diagnostics.Process.Start(System.IO.Path.Combine(exepath, "Launcher-RPA.exe"), "uninstall");
                                        process.WaitForExit();
                                    }
                                }
                            }
                        }*/
                        else // None -> Do nothing
                        {
                            if (isWindowsLocked && launcherCommand == "Play")
                            {
                                launcherCommand = "None";
                                Log.Information("isWindowsLocked..Start session for process " + process_id);
                                var session = sessions.Where(x => x.client.processid == process_id).FirstOrDefault();
                                if (session == null)
                                {
                                    unattendedclient client = new unattendedclient();
                                    client.processid = process_id;
                                    client.windowsusername = PluginConfig.windowsusername;
                                    client.windowspassword = PluginConfig.windowspassword;
                                    client.enabled = true;
                                    sessions.Add(new RobotUserSession(client));

                                    // waiting until login success
                                }
                                // Start Launcher-RPA.exe with process_id
                                var asm = System.Reflection.Assembly.GetEntryAssembly();
                                var filepath = asm.CodeBase.Replace("file:///", "");
                                var exepath = System.IO.Path.GetDirectoryName(filepath);
                                if (System.IO.File.Exists(System.IO.Path.Combine(exepath, "Launcher-RPA.exe")))
                                {
                                    Log.Information("Sending to launcher: " + System.IO.Path.Combine(exepath, "Launcher-RPA.exe"));
                                    Log.Information("with arguments: " + process_id + " /");
                                    var process = System.Diagnostics.Process.Start(System.IO.Path.Combine(exepath, "Launcher-RPA.exe"), process_id + " " + launcherCommand);
                                    //process.WaitForExit();
                                }
                                else
                                {
                                    Log.Information("1.File Launcher-RPA.exe is not existed at " + exepath);
                                }
                            }
                        }
                    }
                    await Task.Delay(PluginConfig.processiddelaytime);
                }
#else
                string computername = NativeMethods.GetHostName().ToLower();
                string computerfqdn = NativeMethods.GetFQDN().ToLower();

                var servers = await global.webSocketClient.Query<unattendedserver>("openrpa", "{'_type':'unattendedserver', 'computername':'" + computername + "', 'computerfqdn':'" + computerfqdn + "'}");
                unattendedserver server = servers.FirstOrDefault();

                unattendedclient[] clients = new unattendedclient[] { };
                if(server != null && server.enabled)
                {
                    disabledmessageshown = false;
                    clients = await global.webSocketClient.Query<unattendedclient>("openrpa", "{'_type':'unattendedclient', 'computername':'" + computername + "', 'computerfqdn':'" + computerfqdn + "'}");
                } else if (disabledmessageshown == false)
                {
                    Log.Information("No server for " + computerfqdn + " found, or server is disabled");
                    disabledmessageshown = true;
                }
                var sessioncount = sessions.Count();
                foreach (var c in clients)
                {
                    var session = sessions.Where(x => x.client.windowsusername == c.windowsusername).FirstOrDefault();
                    if (session == null)
                    {
                        if(c.enabled)
                        {
                            Log.Information("Adding session for " + c.windowsusername);
                            sessions.Add(new RobotUserSession(c));
                        }
                    }
                    else
                    {
                        if (c._modified != session.client._modified || c._version != session.client._version)
                        {
                            if (c.enabled)
                            {
                                Log.Information("Removing:1 session for " + session.client.windowsusername);
                                sessions.Remove(session);
                                session.Dispose();
                                session = null;
                                Log.Information("Adding session for " + c.windowsusername);
                                sessions.Add(new RobotUserSession(c));
                            } 
                            else
                            {
                                await session.SendSignout();
                                if (session.rdp!=null || session.freerdp !=null)
                                {
                                    Log.Information("disconnecting session for " + session.client.windowsusername);
                                    try
                                    {
                                        session.disconnectrdp();
                                    }
                                    catch (Exception ex)
                                    {
                                        Log.Error(ex.ToString());
                                    }
                                }
                                session.client = c;
                            }
                        }
                    }
                }
                foreach (var session in sessions.ToList())
                {
                    var c = clients.Where(x => x.windowsusername == session.client.windowsusername).FirstOrDefault();
                    if (c == null && session.client != null && !string.IsNullOrEmpty(session.client._id))
                    {
                        Log.Information("Removing:2 session for " + session.client.windowsusername);
                        sessions.Remove(session);
                        session.Dispose();
                        //if (session.connection == null)
                        //{
                        //}
                    }
                }
                if (sessioncount != sessions.Count())
                {
                    Log.Information("Currently have " + sessions.Count() + " sessions");
                }

                // Log.Information("Loaded " + sessions.Count + " sessions");
#endif
            }
            catch (Exception ex)
            {
                Log.Error(ex.ToString());
            }
        }
        public static List<RobotUserSession> sessions = new List<RobotUserSession>();
        // read all process from config.dat file and save to processIds
        public static List<string> processIds = new List<string>();
        private static void Pipe_ClientConnected(NamedPipeWrapper.NamedPipeConnection<RPAMessage, RPAMessage> connection)
        {
            Log.Information("Client connected!");
        }
        private static async void Pipe_ClientMessage(NamedPipeWrapper.NamedPipeConnection<RPAMessage, RPAMessage> connection, RPAMessage message)
        {
            try
            {
                if (message.command == "pong") return;
                if (message.command == "hello")
                {
                    var windowsusername = message.windowsusername.ToLower();
                    var session = sessions.Where(x => x.client.windowsusername == windowsusername).FirstOrDefault();
                    if (session == null)
                    {
                        //Log.Information("Adding new unattendedclient for " + windowsusername);
                        string computername = NativeMethods.GetHostName().ToLower();
                        string computerfqdn = NativeMethods.GetFQDN().ToLower();
                        var client = new unattendedclient() { computername = computername, computerfqdn = computerfqdn, windowsusername = windowsusername, name = computername + " " + windowsusername, openrpapath = message.openrpapath };
                        // client = await global.webSocketClient.InsertOne("openrpa", 1, false, client);
                        session = new RobotUserSession(client);
                        sessions.Add(session);
                    }
                    if (session.client != null)
                    {
                        session.client.openrpapath = message.openrpapath;
                        session.AddConnection(connection);
                    }
                }
                if (message.command == "reloadconfig")
                {
                    await ReloadConfig();
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex.ToString());
            }
        }
        public static OpenRPA.NamedPipeWrapper.NamedPipeServer<RPAMessage> pipe = null;
        private static void DoWork()
        {
            try
            {
                log("BEGIN::Set ProjectsDirectory");
                // Don't mess with ProjectsDirectory if we need to reauth
                if (args.Length == 0) Log.ResetLogPath(logpath);

                log("Set UnhandledException");
                AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(CurrentDomain_UnhandledException);
                System.Threading.Thread.Sleep(1000 * StartupWaitSeconds);
                _ = PluginConfig.reloadinterval;
                _ = PluginConfig.jwt;
                _ = PluginConfig.wsurl;
                _ = PluginConfig.width;
                _ = PluginConfig.height;
                _ = PluginConfig.height;
                // TODO: Why only use freerdp if has some argument?
                if (args.Length != 0)
                {
                    try
                    {
                        log("Get usefreerdp");
                        if (PluginConfig.usefreerdp)
                        {
                            log("Init Freerdp");
                            using (var rdp = new FreeRDP.Core.RDP())
                            {
                            }
                        }
                    }
                    catch (Exception)
                    {
                        Log.Information("Failed initilizing FreeRDP, is Visual C++ Runtime installed ?");
                        // Log.Information("https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads");
                        Log.Information("https://www.microsoft.com/en-us/download/details.aspx?id=40784");
                        return;
                    }
                }
                if (args.Length == 0)
                {
                    if(PluginConfig.useasservice)
                    {
                        log("Check IsServiceInstalled");
                        // System.Threading.Thread.Sleep(1000 * StartupWaitSeconds);
                        if (!manager.IsServiceInstalled)
                        {
                            //Console.Write("Username (" + NativeMethods.GetProcessUserName() + "): ");
                            //var username = Console.ReadLine();
                            //if (string.IsNullOrEmpty(username)) username = NativeMethods.GetProcessUserName();
                            //Console.Write("Password: ");
                            //string pass = "";
                            //do
                            //{
                            //    ConsoleKeyInfo key = Console.ReadKey(true);
                            //    if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                            //    {
                            //        pass += key.KeyChar;
                            //        Console.Write("*");
                            //    }
                            //    else
                            //    {
                            //        if (key.Key == ConsoleKey.Backspace && pass.Length > 0)
                            //        {
                            //            pass = pass.Substring(0, (pass.Length - 1));
                            //            Console.Write("\b \b");
                            //        }
                            //        else if (key.Key == ConsoleKey.Enter)
                            //        {
                            //            break;
                            //        }
                            //    }
                            //} while (true);
                            //manager.InstallService(typeof(Program), new string[] { "username=" + username, "password=" + pass });
                            log("InstallService");
                            manager.InstallService(typeof(Program), new string[] { });
                        }
                    }
                }
                if (args.Length > 0)
                {
                    if (args[0].ToLower() == "auth" || args[0].ToLower() == "reauth")
                    {
                        if (Config.local.jwt != null && Config.local.jwt.Length > 0)
                        {
                            Log.Information("Saving temporart jwt token, from local settings.json");
                            PluginConfig.tempjwt = new System.Net.NetworkCredential(string.Empty, Config.local.UnprotectString(Config.local.jwt)).Password;
                            PluginConfig.wsurl = Config.local.wsurl;
                            PluginConfig.Save();
                        }
                        return;
                    }
                    else if (args[0].ToLower() == "uninstall" || args[0].ToLower() == "u")
                    {
                        if (manager.IsServiceInstalled)
                        {
                            manager.UninstallService(typeof(Program));
                        }

                        var asm = System.Reflection.Assembly.GetEntryAssembly();
                        var filepath = asm.CodeBase.Replace("file:///", "");
                        var exepath = System.IO.Path.GetDirectoryName(filepath);
                        if (System.IO.File.Exists(System.IO.Path.Combine(exepath, "OpenRPA.RDServiceMonitor.exe")))
                        {
                            var process = System.Diagnostics.Process.Start(System.IO.Path.Combine(exepath, "OpenRPA.RDServiceMonitor.exe"), "uninstall");
                            process.WaitForExit();
                        }
                        return;
                    }
                    else if (args[0].ToLower() == "service" || args[0].ToLower() == "s")
                    {
                        /*PluginConfig.wsurl = "wss://app.openiap.io/";
                        PluginConfig.jwt = "ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKSVV6STFOaUo5LmV5SnBjM01pT2lKUGJteHBibVVnU2xkVUlFSjFhV3hrWlhJaUxDSnBZWFFpT2pFMk1UZzVOVE15T1RVc0ltVjRjQ0k2TVRZMU1EUTRPVEk1TlN3aVlYVmtJam9pZDNkM0xtVjRZVzF3YkdVdVkyOXRJaXdpYzNWaUlqb2lhbkp2WTJ0bGRFQmxlR0Z0Y0d4bExtTnZiU0lzSW5WelpYSnVZVzFsSWpvaVFtOXVRbTl1SWl3aWNHRnpjM2R2Y21RaU9pSXhJaXdpWlc1MGNtOXdlU0k2SWtwMWJtZENUR2hoZFVjclNuWlJhWEJyVVZCSmNEbHpUSGRLZHowaWZRLlBnN0F3dFJQYWZnbnMwbmNmZ2hvRmRJZ19aXzRFalY5VEdvSm5hYW9GSE0=";
                        PluginConfig.entropy = "JungBLhauG+JvQipkQPIp9sLwJw=";*/
                        /*PluginConfig.usefreerdp = false;
                        PluginConfig.windowsusername = "desktop-21o96l8\\hec_205";
                        PluginConfig.windowspassword = "nothing123";
                        PluginConfig.Save();*/
                    }
                    else
                    {
                        Log.Information("unknown command " + args[0]);
                        Log.Information("try uninstall or reauth ");
                        return;
                    }
                    
                }


                log("Create Tracing");
                tracing = new Tracing(Console.Out);
                log("Add Tracing");
                System.Diagnostics.Trace.Listeners.Add(tracing);
                log("Override SetOut");
                Console.SetOut(new ConsoleDecorator(Console.Out));
                log("Override SetError");
                Console.SetError(new ConsoleDecorator(Console.Out, true));
                log("ResetLogPath");
                Log.ResetLogPath(logpath);
                Log.Information("****** BEGIN");

                /* Here is the actual working Task */
                WebSocketClient_OnOpen();
                //Task.Run(async () => {
                //    try
                //    {
                //       /* Log.Information("Connect to " + PluginConfig.wsurl);
                //        global.webSocketClient = new WebSocketClient(PluginConfig.wsurl);
                //        global.webSocketClient.OnOpen += WebSocketClient_OnOpen;
                //        global.webSocketClient.OnClose += WebSocketClient_OnClose;
                //        global.webSocketClient.OnQueueMessage += WebSocketClient_OnQueueMessage;
                //        await global.webSocketClient.Connect();*/
                //    }
                //    catch (Exception ex)
                //    {
                //        Log.Error(ex.ToString());
                //    }
                //});
                // NativeMethods.AllocConsole();
                // if (System.Diagnostics.Debugger.IsAttached && !isService)
                if (!Monitormanager.IsServiceInstalled)
                {
                    var asm = System.Reflection.Assembly.GetEntryAssembly();
                    var filepath = asm.CodeBase.Replace("file:///", "");
                    var exepath = System.IO.Path.GetDirectoryName(filepath);
                    if (System.IO.File.Exists(System.IO.Path.Combine(exepath, "OpenRPA.RDServiceMonitor.exe")))
                    {
                        var process = System.Diagnostics.Process.Start(System.IO.Path.Combine(exepath, "OpenRPA.RDServiceMonitor.exe"));
                        process.WaitForExit();
                    }
                }
                if (!isService)
                {
                    if (args.Length > 0 && (args[0].ToLower() == "service" || args[0].ToLower() == "s"))
                    {
                        // Manually set current run as "service", for dev purpose maybe?
                        isService = true;
                    }
                    Log.Information("******************************");
                    Log.Information("* Done                       *");
                    Log.Information("******************************");
                    Console.ReadLine();
                }
                else
                {
                    /* If we are started as a service then trying to start the Monitor service as well. After that it will quit. */
                    if (Monitormanager.IsServiceInstalled)
                    {
                        _ = Monitormanager.StartService();
                    }
                    while (MyServiceBase.isRunning)
                    {
                        System.Threading.Thread.Sleep(100);
                    }
                    if(Monitormanager.IsServiceInstalled)
                    {
                        // _ = Monitormanager.StopService();
                    }
                }
            }
            catch (Exception ex) 
            {
                Log.Error(ex.ToString());
            }
        }
    }
}
