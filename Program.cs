using ProtoMcp;

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
try
{
    await McpServer.RunAsync(cts.Token);
}
catch (OperationCanceledException) { }
