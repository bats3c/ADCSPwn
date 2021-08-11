using System;
using System.Collections.Generic;
using System.IO;

namespace ADCSPwn
{
    class Config
    {
        public static int port = 8080;
        public static string machine = "localhost";
        public static string adcs = "";
        public static bool secure = false;

        public static string username = "";
        public static string password = "";
        public static string dc = "";
        public static string unc = "";
        public static string outpath = "";

        public static string banner = @"
   _____  ________  _________   ___________________                
  /  _  \ \______ \ \_   ___ \ /   _____/\______   \__  _  ______  
 /  /_\  \ |    |  \/    \  \/ \_____  \  |     ___/\ \/ \/ /    \ 
/    |    \|    `   \     \____/        \ |    |     \     /   |  \
\____|__  /_______  /\______  /_______  / |____|      \/\_/|___|  /
        \/        \/        \/        \/                        \/ 
";
    }
}
