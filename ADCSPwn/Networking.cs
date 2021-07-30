using System;
using System.ComponentModel;
using System.DirectoryServices;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace ADCSPwn
{
    /*
     *  Stolen from the awesome Rubeus project by @harmj0y (primary author) and many many more!
     * https://github.com/GhostPack/Rubeus
     * 
    */

  
    public class Networking
    {

        public static string GetIPAddress(string hostname)
        {
            IPHostEntry host;
            host = Dns.GetHostEntry(hostname);

            foreach (IPAddress ip in host.AddressList)
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    //System.Diagnostics.Debug.WriteLine("LocalIPadress: " + ip);
                    return ip.ToString();
                }
            }
            return string.Empty;
        }

        public static DirectoryEntry GetLdapSearchRoot(System.Net.NetworkCredential cred, string OUName, string domainController, string domain)
        {
            DirectoryEntry directoryObject = null;
            string ldapPrefix = "";
            string ldapOu = "";

            //If we have a DC then use that instead of the domain name so that this works if user doesn't have
            //name resolution working but specified the IP of a DC
            if (!String.IsNullOrEmpty(domainController))
            {
                ldapPrefix = domainController;
            }
            else if (!String.IsNullOrEmpty(domain)) //If we don't have a DC then use the domain name (if we have one)
            {
                ldapPrefix = domain;
            }
            else if (cred != null) //If we don't have a DC or a domain name but have credentials, get domain name from them
            {
                ldapPrefix = cred.Domain;
            }

            if (!String.IsNullOrEmpty(OUName))
            {
                ldapOu = OUName.Replace("ldap", "LDAP").Replace("LDAP://", "");
            }
            else if (!String.IsNullOrEmpty(domain))
            {
                ldapOu = String.Format("DC={0}", domain.Replace(".", ",DC="));
            }

            //If no DC, domain, credentials, or OU were specified
            if (String.IsNullOrEmpty(ldapPrefix) && String.IsNullOrEmpty(ldapOu))
            {
                directoryObject = new DirectoryEntry();
            }
            else //If we have a prefix (DC or domain), an OU path, or both
            {
                string bindPath = "";
                if (!String.IsNullOrEmpty(ldapPrefix))
                {
                    bindPath = String.Format("LDAP://{0}", ldapPrefix);
                }
                if (!String.IsNullOrEmpty(ldapOu))
                {
                    if (!String.IsNullOrEmpty(bindPath))
                    {
                        bindPath = String.Format("{0}/{1}", bindPath, ldapOu);
                    }
                    else
                    {
                        bindPath = String.Format("LDAP://{1]", ldapOu);
                    }
                }

                directoryObject = new DirectoryEntry(bindPath);
            }

            if (cred != null)
            {
                // if we're using alternate credentials for the connection
                //string userDomain = String.Format("{0}\\{1}", cred.Domain, cred.UserName);
                directoryObject.Username = cred.UserName;
                directoryObject.Password = cred.Password;

                // Removed credential validation check because it just caused problems and doesn't gain us anything (if invalid
                // credentials are specified, the LDAP search will fail with "Logon failure: bad username or password" anyway)

                //string contextTarget = "";
                //if (!string.IsNullOrEmpty(domainController))
                //{
                //    contextTarget = domainController;
                //}
                //else
                //{
                //    contextTarget = cred.Domain;
                //}

                //using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, contextTarget))
                //{
                //    if (!pc.ValidateCredentials(cred.UserName, cred.Password))
                //    {
                //        throw new Exception(String.Format("\r\n[X] Credentials supplied for '{0}' are invalid!", userDomain));
                //    }
                //    else
                //    {
                //        Console.WriteLine("[*] Using alternate creds  : {0}", userDomain);
                //    }
                //}
            }
            return directoryObject;
        }



    }

}
