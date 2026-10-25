using Serilog;
Log.Logger = new LoggerConfiguration().WriteTo.Console().CreateLogger();
Log.Information("Hello {Who}", "REA");
