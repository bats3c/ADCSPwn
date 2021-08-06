using System;
using System.IO;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Collections.Generic;

namespace ADCSPwn
{
    class TemplateHunter
    {
        String Base = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=";

        private string username;
        private string password;
        private string dc;

        public TemplateHunter(string username, string password, string domainController)
        {
            this.username = username;
            this.password = password;
            this.dc = domainController;
        }

        public String[] FindAll()
        {

            DirectoryEntry DirEntry = null;
            DirectorySearcher DirSearch = null;

            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password) && !string.IsNullOrEmpty(dc))
            {
                //Create some network credentials 
                string domain = username.Split('\\')[0];
                var netCred = new System.Net.NetworkCredential(username, password, domain);
                DirEntry = Networking.GetLdapSearchRoot(netCred, Base + netCred?.Domain.Replace(".", ",DC="), dc, netCred?.Domain);
                DirSearch = new DirectorySearcher(DirEntry);
            }else if (!string.IsNullOrEmpty(dc))
            {
                DirEntry = Networking.GetLdapSearchRoot(null
                    , Base + System.DirectoryServices.ActiveDirectory.Domain.GetComputerDomain().ToString().Replace(".", ",DC=")
                    , dc
                    , System.DirectoryServices.ActiveDirectory.Domain.GetComputerDomain().ToString());
                DirSearch = new DirectorySearcher(DirEntry);
            }
            else
            {
                String LdapBase = Base + System.DirectoryServices.ActiveDirectory.Domain.GetComputerDomain().ToString().Replace(".", ",DC=");
                DirEntry = new DirectoryEntry(LdapBase);
                DirSearch = new DirectorySearcher(DirEntry);
            }


            DirSearch.Filter = "(&(name=*))";
            DirSearch.PageSize = Int32.MaxValue;

            var Templates = new List<string>() { };
            foreach (SearchResult Result in DirSearch.FindAll())
            {
                try
                {
                    Templates.Add(Result.Properties["name"][0].ToString());
                }
                catch (Exception ex)
                {

                    //We failed to get the name of a template. ignore
                }
            

            }

            return Templates.ToArray();
        }
    }
}
