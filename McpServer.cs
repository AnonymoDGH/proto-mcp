using System.Text.Json.Nodes;

namespace ProtoMcp;

public sealed record ToolResult(bool IsError, string Text, JsonNode? Structured);
public sealed record ToolDef(
    string Name,
    string Description,
    JsonObject Schema,
    Func<JsonObject, CancellationToken, Task<ToolResult>> Handler);

public static class McpServer
{
    private static readonly Dictionary<string, ToolDef> Tools = new(StringComparer.Ordinal);

    public static void Add(string name, string description, string schemaJson,
        Func<JsonObject, CancellationToken, Task<ToolResult>> handler)
    {
        var schema = JsonNode.Parse(schemaJson)!.AsObject();
        Tools[name] = new ToolDef(name, description, schema, handler);
    }

    public static ToolResult Ok(JsonObject structured)
        => new(false, structured.ToJsonString(), structured);

    public static ToolResult Fail(string message)
    {
        var j = new JsonObject { ["error"] = message };
        return new(true, j.ToJsonString(), j);
    }

    public static async Task RunAsync(CancellationToken ct)
    {
        McTools.RegisterAll();

        while (!ct.IsCancellationRequested)
        {
            string? line;
            try { line = await Console.In.ReadLineAsync(); }
            catch { break; }
            if (line is null) break;
            line = line.Trim();
            if (line.Length == 0) continue;

            JsonObject? req = null;
            try { req = JsonNode.Parse(line)?.AsObject(); }
            catch { await WriteAsync(RpcError(null, -32700, "parse error")); continue; }
            if (req is null) { await WriteAsync(RpcError(null, -32700, "parse error")); continue; }

            JsonObject? resp;
            try { resp = await HandleAsync(req, ct); }
            catch (Exception ex) { resp = RpcError(req["id"], -32603, "internal error: " + ex.Message); }

            if (resp is not null) await WriteAsync(resp);
        }
    }

    private static Task WriteAsync(JsonObject resp)
        => Console.Out.WriteLineAsync(resp.ToJsonString());

    private static JsonNode? CloneId(JsonNode? id)
        => id is null ? null : JsonNode.Parse(id.ToJsonString());

    private static JsonObject RpcResult(JsonNode? id, JsonNode result)
    {
        var r = new JsonObject { ["jsonrpc"] = "2.0", ["result"] = result };
        r["id"] = CloneId(id);
        return r;
    }

    private static JsonObject RpcError(JsonNode? id, int code, string message)
    {
        var r = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["error"] = new JsonObject { ["code"] = code, ["message"] = message }
        };
        r["id"] = CloneId(id);
        return r;
    }

    private static async Task<JsonObject?> HandleAsync(JsonObject req, CancellationToken ct)
    {
        JsonNode? id = req["id"];
        bool isNotification = id is null;
        string method = req["method"]?.GetValue<string>() ?? "";
        var pars = req["params"]?.AsObject() ?? new JsonObject();

        if (method == "initialize")
        {
            string pv = pars["protocolVersion"]?.GetValue<string>() ?? "2024-11-05";
            var result = new JsonObject
            {
                ["protocolVersion"] = pv,
                ["capabilities"] = new JsonObject { ["tools"] = new JsonObject() },
                ["serverInfo"] = new JsonObject
                {
                    ["name"] = "proto-mcp",
                    ["version"] = "0.1.0",
                    ["title"] = "proto-mcp — Minecraft server recon and access toolkit"
                },
                ["instructions"] = "Minecraft Java server toolkit: resolve, status ping, fingerprint, " +
                    "GameSpy query, RCON probe/brute, offline join probe, and an auto recon pipeline. " +
                    "Input is just host[:port]; output is a structured access assessment."
            };
            return RpcResult(id, result);
        }

        if (method is "notifications/initialized" or "initialized" or "notifications/cancelled")
            return null;

        if (method == "ping")
            return RpcResult(id, new JsonObject());

        if (method == "tools/list")
        {
            var arr = new JsonArray();
            foreach (var t in Tools.Values)
            {
                arr.Add(new JsonObject
                {
                    ["name"] = t.Name,
                    ["description"] = t.Description,
                    ["inputSchema"] = t.Schema.DeepClone()
                });
            }
            return RpcResult(id, new JsonObject { ["tools"] = arr });
        }

        if (method == "tools/call")
        {
            string name = pars["name"]?.GetValue<string>() ?? "";
            var args = pars["arguments"]?.AsObject() ?? new JsonObject();
            if (!Tools.TryGetValue(name, out var tool))
            {
                var notFound = new JsonObject { ["error"] = "unknown tool: " + name };
                return RpcResult(id, new JsonObject
                {
                    ["content"] = new JsonArray { new JsonObject { ["type"] = "text", ["text"] = notFound.ToJsonString() } },
                    ["isError"] = true,
                    ["structuredContent"] = notFound
                });
            }

            ToolResult tr;
            try { tr = await tool.Handler(args, ct); }
            catch (Exception ex) { tr = Fail("exception: " + ex.Message); }

            JsonNode sc = tr.Structured is JsonObject o ? o.DeepClone() : new JsonObject { ["value"] = tr.Structured?.DeepClone() };
            return RpcResult(id, new JsonObject
            {
                ["content"] = new JsonArray { new JsonObject { ["type"] = "text", ["text"] = tr.Text } },
                ["isError"] = tr.IsError,
                ["structuredContent"] = sc
            });
        }

        if (isNotification) return null;
        return RpcError(id, -32601, "method not found: " + method);
    }
}
