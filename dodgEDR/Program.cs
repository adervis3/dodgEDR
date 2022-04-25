using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace dodgEDR
{

    class Program
    {
        // https://csharp.hotexamples.com/examples/System.Security.Cryptography.X509Certificates/X509Certificate2/GetEffectiveDateString/php-x509certificate2-geteffectivedatestring-method-examples.html
        private static bool check_cert(string Path, string file)
        {
            string filePath = Path + "\\" + file;
            X509Certificate2 theCertificate;
            try
            {
                X509Certificate theSigner = X509Certificate.CreateFromSignedFile(filePath);
                theCertificate = new X509Certificate2(theSigner);
                Console.WriteLine("--- FILE INFO ---");
                Console.WriteLine(FileVersionInfo.GetVersionInfo(filePath) + "\n\n");
                Console.WriteLine("--- CERTIFICATION INFO ---");
                //Console.WriteLine("Publisher Information : " + theCertificate.SubjectName.Name);
                //Console.WriteLine("Valid From: " + theCertificate.GetEffectiveDateString());
                //Console.WriteLine("Valid To: " + theCertificate.GetExpirationDateString());
                Console.WriteLine("Certificate Verified: " + theCertificate.Verify());
                Console.WriteLine("Issued By: " + theCertificate.Issuer + "\n\n");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("No digital signature found: " + ex.Message + "[!] Driver File Was Found But It's Unsigned!!!\n[!] File Path ...: " + filePath);
                return false;
            }
        }


        private static void check_EDR(string file, string directory)
        {
            try
            {
                // https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes
                switch (file.ToLower())
                {
                    case "csacentr.sys":
                    case "csaenh.sys":
                    case "csareg.sys":
                    case "csascr.sys":
                    case "csaav.sys":
                    case "csaam.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Cisco Systems Secure Endpoint");
                        break;
                    case "fsgk.sys":
                    case "fshs.sys":
                    case "fsatp.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("F-Secure");
                        break;
                    case "eaw.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Raytheon Cyber Solutions");
                        break;
                    case "im.sys":
                    case "csagent.sys":
                    case "csim.sys":
                    case "csimn.sys":
                    case "csimu.sys":
                    case "imbs.sys":
                    case "csboot.sys":
                    case "csdevicecontrol.sys":
                    case "cspcm2.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Falcon Insight (CrowdStrike)");
                        break;
                    case "rvsavd.sys":
                    case "rvsmon.sys":
                    case "skycryptorencfs.sys":
                    case "rmseffmv.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: CJSC Returnil Software");
                        break;
                    case "dgdmk.sys":
                    case "stkrnl64.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Verdasys DLP");
                        break;
                    case "mbig2prot.sys":
                    case "mbamwatchdog.sys":
                    case "mbamshuriken.sys":
                    case "flightrecorder.sys":
                    case "mbam.sys":
                    case "farwflt.sys":
                    case "mbamapiary.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Malwarebytes");
                        break;
                    case "edevmon.sys":
                    case "ehdrv.sys":
                    case "eamonm.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: ESET XDR");
                        break;
                    case "sentinelmonitor.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: SentinelOne");
                        break;
                    case "hbflt.sys":
                    case "vlflt.sys":
                    case "bdsvm.sys":
                    case "gzflt.sys":
                    case "bddevflt.sys":
                    case "ignis.sys":
                    case "avckf.sys":
                    case "gemma.sys":
                    case "atc.sys":
                    case "avc3.sys":
                    case "trufos.sys":
                    case "bdsandbox.sys":
                    case "edrsensor.sys":
                    case "bdprivmon.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Bitdefender");
                        break;
                    case "hexisfsmonitor.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Hexis Cyber Solutions");
                        break;
                    case "cyoptics.sys":
                    case "cyprotectdrv32.sys":
                    case "cyprotectdrv64.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: CylancePROTECT");
                        break;
                    case "cbk7.sys":
                    case "cbstream.sys":
                    case "carbonblackk.sys":
                    case "cbtdiflt.sys":
                    case "ctifile.sys":
                    case "ctinet.sys":
                    case "cbelam.sys":
                    case "cbdisk.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: VMware Carbon Black Endpoint");
                        break;
                    case "crexecprev.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Cybereason XDR");
                        break;
                    case "ssfmonm.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Webroot Business Endpoint Protection");
                        break;
                    case "cybkerneltracker.sys":
                    case "vfpd.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: CyberArk Security Solutions");
                        break;
                    case "sophosed.sys":
                    case "soidriver.sys":
                    case "savonaccess.sys":
                    case "sld.sys":
                    case "sophosdt2.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Sophos EDR");
                        break;
                    case "aswsp.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Avast Antivirus");
                        break;
                    case "fekern.sys":
                    case "wfp_mrt.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: FireEye EDR");
                        break;
                    case "klifks.sys":
                    case "klifaa.sys":
                    case "klifsm.sys":
                    case "klboot.sys":
                    case "klfdefsf.sys":
                    case "klrsps.sys":
                    case "klsnsr.sys":
                    case "klam.sys":
                    case "klbg.sys":
                    case "kldback.sys":
                    case "kldlinf.sys":
                    case "kldtool.sys":
                    case "klif.sys":
                    case "klcdp.sys":
                    case "klshadow.sys":
                    case "klsysrec.sys":
                    case "klvfs.sys":
                    case "klfle.sys":
                    case "klvirt.sys":
                    case "klbackupflt.sys":
                    case "klsec.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Kaspersky Endpoint Detection and Response");
                        break;
                    case "mfeaskm.sys":
                    case "mfencfilter.sys":
                    case "epdrv.sys":
                    case "mfencoas.sys":
                    case "mfehidk.sys":
                    case "swin.sys":
                    case "hdlpflt.sys":
                    case "mfprom.sys":
                    case "mfeeeff.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Mvision EDR (McAfee Inc.)");
                        break;
                    case "groundling32.sys":
                    case "groundling64.sys	":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Taegis EDR (Dell Secureworks)");
                        break;
                    case "safe-agent.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Forti EDR");
                        break;
                    case "avgtpx86.sys":
                    case "avgtpx64.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: AVG Antivirus");
                        break;
                    case "pgpwdefs.sys":
                    case "geprotection.sys":
                    case "diflt.sys":
                    case "sysmon.sys":
                    case "ssrfsf.sys":
                    case "emxdrv2.sys":
                    case "reghook.sys":
                    case "spbbcdrv.sys":
                    case "bhdrvx86.sys":
                    case "bhdrvx64.sys":
                    case "sisipsfilefilter":
                    case "symevent.sys":
                    case "eectrl.sys":
                    case "eraser.sys (retired)":
                    case "srtsp.sys":
                    case "srtspit.sys":
                    case "srtsp64.sys":
                    case "virtualagent.sys":
                    case "vxfsrep.sys":
                    case "symafr.sys":
                    case "symefa.sys":
                    case "symefa64.sys":
                    case "symhsm.sys":
                    case "evmf.sys":
                    case "gefcmp.sys":
                    case "vfsenc.sys":
                    case "pgpfs.sys":
                    case "fencry.sys":
                    case "appstream.sys":
                    case "symrg.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Symantec Endpoint Protection");
                        break;
                    case "virtfile.sys":
                    case "qafilter.sys":
                    case "FileScreenFilter.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Veritas");
                        break;
                    case "symefasi.sys":
                    case "symefasi64.sys":
                        if (file == "SymEFASI.sys" || file == "SymEFASI64.sys")
                            if (check_cert(directory, file))
                                Console.WriteLine("Found: NortonLifeLock Inc.");
                            else;
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Symantec Endpoint Protection");
                        break;
                    case "cfrmd.sys":
                    case "cmdcwagt.sys":
                    case "cmdccav.sys":
                    case "cmdguard.sys":
                    case "cmdmnefs.sys":
                    case "mydlpmf.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Comodo EDR");
                        break;
                    case "psinproc.sys":
                    case "psinfile.sys":
                    case "amfsm.sys":
                    case "amm8660.sys":
                    case "amm6460.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Panda Antivirus");
                        break;
                    case "avipbb.sys":
                    case "avgntflt.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Avira Antivirus");
                        break;
                    case "tmums.sys":
                    case "hfileflt.sys":
                    case "tmumh.sys":
                    case "acdriver.sys":
                    case "sakfile.sys":
                    case "sakmfile.sys":
                    case "tmkmsnsr.sys":
                    case "fileflt.sys":
                    case "tmesflt.sys":
                    case "tmeyes.sys":
                    case "tmevtmgr.sys":
                    case "tmfileencdmk.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Trend Micro Apex One Endpoint Security");
                        break;
                    case "cyvrfsfd.sys":
                    case "tedrdrv.sys":
                        // Another Palo Alto Drivers:
                        // https://docs.paloaltonetworks.com/cortex/cortex-xdr/7-4/cortex-xdr-agent-admin/cortex-xdr-agent-for-windows/troubleshoot-cortex-xdr-for-windows 
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Cortex XDR (Palo Alto Networks)");
                        break;
                    case "epregflt.sys":
                    case "epklib.sys":
                    case "medlpflt.sys":
                    case "dsfa.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Harmony Endpoint (Check Point)");
                        break;
                    case "cve.sys":
                    case "cbfsfilter2017.sys":
                    case "psepfilter.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Absolute Visibility");
                        break;
                    case "brfilter.sys":
                    case "bemk.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: Bromium Endpoint Protection");
                        break;
                    case "lragentMF.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: LogRhythm UserXDR");
                        break;
                    case "libwamf.sys":
                        if (check_cert(directory, file))
                            Console.WriteLine("Found: MetaDefender");
                        break;
                    default:
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n" + ex.Message);
            }

        }



        // https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/file-system/how-to-iterate-through-a-directory-tree
        public static void TraverseTree(string root)
        {
            // Data structure to hold names of subfolders to be
            // examined for files.
            Stack<string> dirs = new Stack<string>(0);

            if (!System.IO.Directory.Exists(root))
            {
                throw new ArgumentException();
            }
            dirs.Push(root);

            while (dirs.Count > 0)
            {
                string currentDir = dirs.Pop();
                string[] subDirs;
                try
                {
                    subDirs = System.IO.Directory.GetDirectories(currentDir);
                }
                // An UnauthorizedAccessException exception will be thrown if we do not have
                // discovery permission on a folder or file. It may or may not be acceptable
                // to ignore the exception and continue enumerating the remaining files and
                // folders. It is also possible (but unlikely) that a DirectoryNotFound exception
                // will be raised. This will happen if currentDir has been deleted by
                // another application or thread after our call to Directory.Exists. The
                // choice of which exceptions to catch depends entirely on the specific task
                // you are intending to perform and also on how much you know with certainty
                // about the systems on which this code will run.
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine("\n" + e.Message);
                    continue;
                }
                catch (System.IO.DirectoryNotFoundException e)
                {
                    Console.WriteLine("\n" + e.Message);
                    continue;
                }

                string[] files = null;
                try
                {
                    files = System.IO.Directory.GetFiles(currentDir);
                }

                catch (UnauthorizedAccessException e)
                {

                    Console.WriteLine(e.Message);
                    continue;
                }

                catch (System.IO.DirectoryNotFoundException e)
                {
                    Console.WriteLine("\n" + e.Message);
                    continue;
                }
                // Perform the required action on each file here.
                // Modify this block to perform your required task.
                foreach (string file in files)
                {
                    try
                    {
                        // Perform whatever action is required in your scenario.
                        System.IO.FileInfo fi = new System.IO.FileInfo(file);
                        check_EDR(fi.Name, fi.DirectoryName);
                    }
                    catch (System.IO.FileNotFoundException e)
                    {
                        // If file was deleted by a separate application
                        //  or thread since the call to TraverseTree()
                        // then just continue.
                        Console.WriteLine("\n" + e.Message);
                        continue;
                    }
                }
                // Push the subdirectories onto the stack for traversal.
                // This could also be done before handing the files.
                foreach (string str in subDirs)
                    dirs.Push(str);
            }
        }


        static void Main()
        {
            //Banner
            Console.WriteLine("\n      _           _       ______ _____  _____  \n" +
                                "     | |         | |     |  ____|  __ \\|  __ \\ \n" +
                                "   __| | ___   __| | __ _| |__  | |  | | |__) |\n" +
                                "  / _` |/ _ \\ / _` |/ _` |  __| | |  | |  _  / \n" +
                                " | (_| | (_) | (_| | (_| | |____| |__| | | \\ \\ \n" +
                                "  \\__,_|\\___/ \\__,_|\\__, |______|_____/|_|  \\_\\\n" +
                                "                     __/ |                     \n" +
                                "                    |___/                      \n" +
                                "\n" +
                                "\n" +
                                "            Version    : 1.0\n" +
                                "            Author     : Ahmet Derviş\n" +
                                "            www        : ahmetdervis.com\n" +
                                "            Twitter    : @adrvs42\n" +
                                "            Github     : @adervis3\n" +
                                "            Licence    : GNU General Public License v3.0\n\n\n");


            TraverseTree(@"C:\Windows\System32\drivers");

        }

    }

}
