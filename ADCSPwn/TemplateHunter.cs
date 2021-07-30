using System;
using System.IO;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;

namespace ADCSPwn
{
    class TemplateHunter
    {
        String Base = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=";
        public String[] FindAll()
        {
            String LdapBase = Base + System.DirectoryServices.ActiveDirectory.Domain.GetComputerDomain().ToString().Replace(".", ",DC=");

            DirectoryEntry DirEntry = new DirectoryEntry(LdapBase);
            DirectorySearcher DirSearch = new DirectorySearcher(DirEntry);

            DirSearch.Filter = "(&(name=*))";
            DirSearch.PageSize = Int32.MaxValue;

            Int32 iter = 0;
            String[] Templates = new String[1000]; // make this dynamic based on the results count
            foreach (SearchResult Result in DirSearch.FindAll())
            {
                Templates[iter] = Result.Properties["name"][0].ToString();
                iter++;
            }

            return Templates;
        }
    }
}
