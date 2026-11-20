using System.Net;
using Garnet;
using Garnet.server;
using Garnet.server.Auth.Settings;

namespace CyberAudit.WindowsBroker;

internal static class Program
{
    private const int ConfigurationErrorExitCode = 78;

    public static int Main(string[] args)
    {
        if (args is ["--verify-package"])
        {
            Console.WriteLine("CyberAudit Windows broker package verified");
            return 0;
        }

        if (args.Length != 0)
        {
            Console.Error.WriteLine("CyberAudit broker runtime rejected unsupported arguments.");
            return ConfigurationErrorExitCode;
        }

        try
        {
            Run();
            return 0;
        }
        catch (BrokerConfigurationException)
        {
            Console.Error.WriteLine("CyberAudit broker runtime configuration is invalid.");
            return ConfigurationErrorExitCode;
        }
        catch (Exception)
        {
            Console.Error.WriteLine("CyberAudit broker runtime failed safely.");
            return 1;
        }
    }

    private static void Run()
    {
        var directory = ValidatedDirectory(RequiredEnvironment("CYBERAUDIT_BROKER_DIRECTORY"));
        var port = ValidatedPort(RequiredEnvironment("CYBERAUDIT_BROKER_PORT"));
        var password = ValidatedPassword(ReadSecret());

        var options = new GarnetServerOptions
        {
            EndPoints = [new IPEndPoint(IPAddress.Loopback, port)],
            AuthSettings = new PasswordAuthenticationSettings(password),
            EnableAOF = true,
            Recover = Directory.EnumerateFileSystemEntries(directory).Any(),
            FailOnRecoveryError = true,
            WaitForCommit = true,
            CommitFrequencyMs = 1000,
            CheckpointFrequencySecs = 300,
            EnableLua = true,
            LuaTransactionMode = true,
            LuaOptions = new LuaOptions(),
            EnableStorageTier = true,
            LogDir = directory,
            CheckpointDir = directory,
            LogMemorySize = "256m",
            PageSize = "4m",
            SegmentSize = "128m",
            ObjectLogSegmentSize = "128m",
            IndexMemorySize = "32m",
            AofMemorySize = "32m",
            AofPageSize = "8m",
            AofSegmentSize = "128m",
            BufferPoolMemoryBudget = "64m",
            NetworkBufferMemoryBudget = "64m",
            NetworkConnectionLimit = 256,
            DisablePubSub = true,
            QuietMode = true,
        };

        using var stopped = new ManualResetEventSlim(false);
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            stopped.Set();
        };
        AppDomain.CurrentDomain.ProcessExit += (_, _) => stopped.Set();

        using var server = new GarnetServer(options, cleanupDir: false);
        server.Start();
        stopped.Wait();
    }

    private static string RequiredEnvironment(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new BrokerConfigurationException();
        }

        return value;
    }

    private static string ValidatedDirectory(string value)
    {
        if (!Path.IsPathFullyQualified(value))
        {
            throw new BrokerConfigurationException();
        }

        var fullPath = Path.GetFullPath(value);
        if (Path.GetPathRoot(fullPath) == fullPath)
        {
            throw new BrokerConfigurationException();
        }

        Directory.CreateDirectory(fullPath);
        var directory = new DirectoryInfo(fullPath);
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new BrokerConfigurationException();
        }

        return fullPath;
    }

    private static int ValidatedPort(string value)
    {
        if (!int.TryParse(value, out var port) || port is < 1024 or > 65535)
        {
            throw new BrokerConfigurationException();
        }

        return port;
    }

    private static string ValidatedPassword(string? value)
    {
        if (value is null || value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new BrokerConfigurationException();
        }

        return value;
    }

    private static string ReadSecret()
    {
        var buffer = new char[65];
        var length = 0;
        while (true)
        {
            var next = Console.In.Read();
            if (next == -1)
            {
                throw new BrokerConfigurationException();
            }

            if (next == '\n')
            {
                break;
            }

            if (length == buffer.Length)
            {
                throw new BrokerConfigurationException();
            }

            buffer[length++] = (char)next;
        }

        if (length > 0 && buffer[length - 1] == '\r')
        {
            length -= 1;
        }

        return new string(buffer, 0, length);
    }

    private sealed class BrokerConfigurationException : Exception;
}
