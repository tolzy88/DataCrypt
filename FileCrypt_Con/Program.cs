using System.Reflection;
using System.Text;
using DataCrypt;

[assembly: AssemblyTitle("FileCrypt_Con")]
[assembly: AssemblyProduct("FileCrypt_Con")]
[assembly: AssemblyVersion("2.3.*")]
namespace FileCrypt_Con
{
    internal class Program
    {
        static Program()
        {
            Console.InputEncoding = Encoding.Unicode;
            Console.OutputEncoding = Encoding.Unicode;
            Console.WriteLine($"FileCrypt Format Version {FileCrypt.Version}");
        }

        /// <summary>
        /// Program Entry Point.
        /// </summary>
        /// <param name="args">Cmd line args for automation:
        /// /encrypt /decrypt (Required)
        /// -password "password" (Required)</param>
        /// -source "path" (Required)
        /// -dest "path" (Optional)
        /// <returns>Exit Code (0 = Success)</returns>
        static int Main(string[] args)
        {
            // Working vars, startup
            bool cmdLineSession = args.Length > 0;
            bool isEncryptionJob;
            string sourceFile, destFile, password;
            if (cmdLineSession) // Command Line Args (Possibly Scripted/Automated)
            {
                string encryptArg = args.FindArg("/encrypt");
                string decryptArg = args.FindArg("/decrypt");
                if (encryptArg is null && decryptArg is null)
                    throw new ArgumentException("Encryption mode not specified! Use /encrypt or /decrypt.");
                if (encryptArg is not null && decryptArg is not null)
                    throw new ArgumentException("Cannot specify both /encrypt and /decrypt!");
                isEncryptionJob = encryptArg is not null;
                password = args.FindArg("-password");
                sourceFile = args.FindArg("-source");
                destFile = args.FindArg("-dest");
            }
            else // User Present
            {
                destFile = null; // Use default destination
                Console.Write("Drag and drop a file to this window (or enter path): ");
                sourceFile = Console.ReadLine()?.Trim('"').Trim(); // Dragging file to window wraps it in " "
                Console.Write("Choose job type: (e)ncrypt or (d)ecrypt? ");
                var jobType = Console.ReadKey();
                Console.WriteLine();
                if (jobType.Key != ConsoleKey.E &&
                    jobType.Key != ConsoleKey.D)
                    throw new ArgumentException("Invalid job type! Use (e)ncrypt or (d)ecrypt.");
                isEncryptionJob = jobType.Key == ConsoleKey.E;
                Console.Write("Enter Password for Key Derivation: ");
                password = ReadPassword();
            }
            ArgumentException.ThrowIfNullOrEmpty(sourceFile, nameof(sourceFile));
            ArgumentNullException.ThrowIfNull(password, nameof(password));
            ArgumentOutOfRangeException.ThrowIfLessThan(password.Length, 8, nameof(password)); // Enforce minimum password length
            // Begin encryption...
            if (isEncryptionJob)
            {
                Console.WriteLine("Encrypting...");
                FileCrypt.EncryptFileToDisk(
                    password: password,
                    sourceFile: sourceFile,
                    destFile: destFile);
            }
            else
            {
                Console.WriteLine("Decrypting...");
                FileCrypt.DecryptFileToDisk(
                    password: password,
                    sourceFile: sourceFile,
                    destFile: destFile);
            }
            Console.WriteLine("Success!");
            if (!cmdLineSession)
            {
                Console.WriteLine("Press any key to exit.");
                Console.ReadKey(intercept: true);
            }
            return 0;
        }

        /// <summary>
        /// Read a Password securely from the console.
        /// </summary>
        /// <returns>Entered password.</returns>
        private static string ReadPassword()
        {
            var password = new Stack<char>();
            ConsoleKeyInfo key;

            while (true)
            {
                key = Console.ReadKey(intercept: true);

                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }
                else if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Count > 0)
                    {
                        Console.Write("\b \b"); // Erase last '*'
                        password.Pop();
                    }
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    password.Push(key.KeyChar);
                    Console.Write("*");
                }
            }

            return new string(password.Reverse().ToArray());
        }
    }

    public static class Extensions
    {
        /// <summary>
        /// Lookup a cmd line arg.
        /// </summary>
        /// <param name="args">Collection of cmd line args.</param>
        /// <param name="name">Name of arg to lookup.</param>
        /// <returns>Arg value or NULL if not found.</returns>
        public static string FindArg(this string[] args, string name)
        {
            for (int i = 0; i < args.Length; i++)
            {

                if (args[i]?.Equals(name, StringComparison.OrdinalIgnoreCase) ?? false)
                {
                    if (name.StartsWith('-'))
                    {
                        if (i + 1 < args.Length)
                        {
                            return args[i + 1].Trim();
                        }
                    }
                    else if (name.StartsWith('/'))
                    {
                        return true.ToString();
                    }
                }
            }
            return null;
        }
    }
}
