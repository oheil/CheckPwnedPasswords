using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace CheckPwnedPasswords
{
    class Program
    {
        //Length of the SHA1 hash
        const int SHA1LENGTH = 40;

        static void Main(string[] args)
		{
			List<string> filesToSearch = ProcessArguments(args);

            static string ByteArrayToString(byte[] ba)
            {
                string hex = BitConverter.ToString(ba);
                return hex.Replace("-", "");
            }

            byte[] bytes;
            System.Security.Cryptography.SHA1 sha;
            byte[] passwordBytes;
            string asHex;

            while (true)
			{
				//Console.WriteLine("");
				Console.WriteLine("");
				Console.WriteLine("Enter password (leave empty to quit):");

                //var pwd = Console.ReadLine();
                var pwd = string.Empty;
                ConsoleKey key;
                do
                {
                    var keyInfo = Console.ReadKey(intercept: true);
                    key = keyInfo.Key;

                    if (key == ConsoleKey.Backspace && pwd.Length > 0)
                    {
                        Console.Write("\b \b");
                        pwd = pwd[0..^1];
                    }
                    else if (!char.IsControl(keyInfo.KeyChar))
                    {
                        Console.Write("*");
                        pwd += keyInfo.KeyChar;
                    }
                } while (key != ConsoleKey.Enter);
                Console.Write("\n");

                if (string.IsNullOrWhiteSpace(pwd)) return;

                bytes = System.Text.Encoding.UTF8.GetBytes(pwd);
                sha = System.Security.Cryptography.SHA1.Create();
                passwordBytes = sha.ComputeHash(bytes);
                asHex = ByteArrayToString(passwordBytes);
                Console.WriteLine($"Password SHA1 hash is: {asHex}");

                foreach (var file in filesToSearch)
				{
					var sw = new Stopwatch();
					sw.Start();
					var result = Check(asHex, file);
					sw.Stop();

					if (result)
					{
                        Console.WriteLine($"Found in {file} - time taken was {sw.Elapsed.Milliseconds}ms");
						break;
					}
					else
					{
						Console.WriteLine($"NOT found in {file} - time taken was {sw.Elapsed.Milliseconds}ms");
					}

                    if(pwd.Length == SHA1LENGTH)
                    {
                        //pwd is perhaps already a SHA1 hash so check it too
                        Console.WriteLine($"Looking for password as it looks like a SHA hash itself ({SHA1LENGTH} bytes long)");

                        sw.Reset();
                        sw.Start();
                        result = Check(pwd, file);
                        sw.Stop();
                        if (result)
                        {
                            Console.WriteLine($"Found hash in {file} - time taken was {sw.Elapsed.Milliseconds}ms");
                            break;
                        }
                        else
                        {
                            Console.WriteLine($"Hash NOT found in {file} - time taken was {sw.Elapsed.Milliseconds}ms");
                        }
                    }
                }
			}
		}

		private static List<string> ProcessArguments(string[] args)
		{
			List<string> filesToSearch = [];
			List<string> directoriesToSearch = [];

			string baseDataDir = Path.Combine(AppContext.BaseDirectory, "data");
			if (Directory.Exists(baseDataDir))
			{
				directoriesToSearch.Add(baseDataDir);
			}

			foreach (string arg in args)
			{
				if (File.Exists(arg))
				{
					filesToSearch.Add(arg);
				}
				else if (Directory.Exists(arg))
				{
					directoriesToSearch.Add(arg);
				}
			}

			foreach (string dir in directoriesToSearch)
			{
				string[] filesInDirectory = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories);
				foreach (string file in filesInDirectory)
				{
					filesToSearch.Add(file);
				}
			}

			return filesToSearch;
		}

		static bool Check(string asHex, string filename)
        {
            var buffer = new byte[SHA1LENGTH];
            using var sr = File.OpenRead(filename);
            
            //Number of lines
            //var high = (sr.Length / (LINELENGTH + 2)) - 1;
            //As line length is now variable just use the bytes in the file:
            long high = sr.Length;
            long low = 0L;

            while (low <= high)
            {
                long middle = (low + high + 1) / 2;
                //Console.WriteLine($"{low}:{middle}:{high}");
                
                //sr.Seek((LINELENGTH + 2) * ((long)middle), SeekOrigin.Begin);

				//seek to next cr/newline (0d0a) ahead of current position
                bool do_seek = true;
				while (middle >= low+1 && do_seek)
				{
					middle -= 1;
					sr.Seek(middle, SeekOrigin.Begin);
					int ch1 = sr.ReadByte();
                    int ch2 = sr.ReadByte();
                    if (ch1 == 0x0d && ch2 == 0x0a)
                    {
                        //Windows NL(0d0a) and file position is on 0x0d
                        middle += 2;
                        do_seek = false;
                    }
                    if (ch1 == 0x0a)
                    {
                        //Windows NL(0d0a) or Posix NL(0a) and file position is on 0x0a
                        middle += 1;
                        do_seek = false;
                    }
				}
				sr.Seek(middle, SeekOrigin.Begin);

                sr.Read(buffer, 0, SHA1LENGTH);
                var readLine = Encoding.ASCII.GetString(buffer);

                switch (readLine.CompareTo(asHex))
                {
                    case 0:
                        return true;

                    case 1:
                        high = middle - 1;
                        break;

                    case -1:
                        low = middle + 1;
                        break;

                    default:
                        break;
                }
            }
            return false;
        }
    }
}
