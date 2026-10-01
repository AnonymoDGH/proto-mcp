using System.IO.Compression;
using System.Net.Sockets;
using System.Text;

namespace ProtoMcp;

// ---------------------------------------------------------------- RCON (Source RCON)
sealed record RconResult(bool TcpOpen, bool Authed, string? Error, List<string> Log);

static class Rcon
{
    const int SERVERDATA_AUTH = 3;
    const int SERVERDATA_AUTH_RESPONSE = 2;
    const int SERVERDATA_EXECCOMMAND = 2;
    const int SERVERDATA_RESPONSE_VALUE = 0;

    static async Task SendAsync(NetworkStream s, int reqId, int type, string body, CancellationToken ct)
    {
        var payload = Encoding.UTF8.GetBytes(body);
        using var ms = new MemoryStream();
        McIO.WriteIntLE(ms, 10 + payload.Length);
        McIO.WriteIntLE(ms, reqId);
        McIO.WriteIntLE(ms, type);
        ms.Write(payload, 0, payload.Length);
        ms.WriteByte(0); ms.WriteByte(0);
        var b = ms.ToArray();
        await s.WriteAsync(b, ct);
        await s.FlushAsync(ct);
    }

    static async Task<(int reqId, int type, string body)?> ReadOneAsync(
        NetworkStream s, int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            int len = await McIO.ReadIntLEAsync(s, cts.Token);
            if (len < 10 || len > 65536) return null;
            var data = await McIO.ReadExactAsync(s, len, cts.Token);
            int req = BitConverter.ToInt32(data, 0);
            int type = BitConverter.ToInt32(data, 4);
            string body = Encoding.UTF8.GetString(data, 8, len - 10);
            return (req, type, body);
        }
        catch { return null; }
    }

    static async Task<RconResult> AuthOnceAsync(string host, int port, string password,
        int timeoutMs, CancellationToken ct)
    {
        var log = new List<string>();
        TcpClient client;
        try { client = await McIO.ConnectAsync(host, port, timeoutMs, ct); }
        catch (Exception ex) { return new RconResult(false, false, "connect: " + ex.Message, log); }

        using (client)
        using (var stream = client.GetStream())
        {
            try
            {
                const int req = 0x50524F54; // 'PROT'
                await SendAsync(stream, req, SERVERDATA_AUTH, password, ct);

                // The server may emit an empty RESPONSE_VALUE first; collect a few packets.
                bool authed = false;
                bool gotAuth = false;
                for (int i = 0; i < 4; i++)
                {
                    var pkt = await ReadOneAsync(stream, Math.Min(timeoutMs, 3000), ct);
                    if (pkt is null) break;
                    log.Add($"pkt type={pkt.Value.type} id={pkt.Value.reqId}");
                    if (pkt.Value.type == SERVERDATA_AUTH_RESPONSE)
                    {
                        gotAuth = true;
                        if (pkt.Value.reqId == req) { authed = true; break; }
                        if (pkt.Value.reqId == -1) { authed = false; break; }
                    }
                }
                string? err = authed ? null : (gotAuth ? "auth rejected by RCON server" : "no RCON response");
                return new RconResult(true, authed, err, log);
            }
            catch (Exception ex) when (ex is OperationCanceledException or TimeoutException)
            {
                return new RconResult(true, false, "timeout (no RCON response)", log);
            }
            catch (Exception ex)
            {
                return new RconResult(true, false, "rcon: " + ex.Message, log);
            }
        }
    }

    public static Task<RconResult> ProbeAsync(string host, int port, int timeoutMs, CancellationToken ct)
        // A single empty-password auth attempt: detects open RCON without brute-forcing.
        => AuthOnceAsync(host, port, "", timeoutMs, ct);

    public static async Task<(bool ok, List<string> tried, string? error)> BruteAsync(
        string host, int port, string[] passwords, int delayMs, int timeoutMs, CancellationToken ct)
    {
        var tried = new List<string>();
        foreach (var pw in passwords.Take(100))
        {
            ct.ThrowIfCancellationRequested();
            var r = await AuthOnceAsync(host, port, pw, timeoutMs, ct);
            tried.Add(pw);
            if (r.Authed) return (true, tried, null);
            if (!r.TcpOpen) return (false, tried, r.Error);
            if (delayMs > 0) await Task.Delay(delayMs, ct);
        }
        return (false, tried, "password not found in list");
    }

    public static async Task<(bool ok, string output, string? error)> ExecAsync(
        string host, int port, string password, string command, int timeoutMs, CancellationToken ct)
    {
        TcpClient client;
        try { client = await McIO.ConnectAsync(host, port, timeoutMs, ct); }
        catch (Exception ex) { return (false, "", "connect: " + ex.Message); }
        using (client)
        using (var stream = client.GetStream())
        {
            try
            {
                const int req = 0x50524F54;
                await SendAsync(stream, req, SERVERDATA_AUTH, password, ct);
                bool authed = false;
                for (int i = 0; i < 4; i++)
                {
                    var pkt = await ReadOneAsync(stream, Math.Min(timeoutMs, 3000), ct);
                    if (pkt is null) break;
                    if (pkt.Value.type == SERVERDATA_AUTH_RESPONSE && pkt.Value.reqId == req) { authed = true; break; }
                    if (pkt.Value.type == SERVERDATA_AUTH_RESPONSE && pkt.Value.reqId == -1) break;
                }
                if (!authed) return (false, "", "auth rejected");

                const int creq = 0x434D4421;
                await SendAsync(stream, creq, SERVERDATA_EXECCOMMAND, command, ct);
                var sb = new StringBuilder();
                for (int i = 0; i < 8; i++)
                {
                    var pkt = await ReadOneAsync(stream, 1500, ct);
                    if (pkt is null) break;
                    if (pkt.Value.type == SERVERDATA_RESPONSE_VALUE && pkt.Value.reqId == creq)
                        sb.Append(pkt.Value.body.TrimEnd('\0'));
                }
                return (true, sb.ToString(), null);
            }
            catch (Exception ex) { return (false, "", "rcon exec: " + ex.Message); }
        }
    }
}

// ---------------------------------------------------------------- offline join probe
sealed record JoinResult(
    bool Joined, bool OnlineModeRequired, bool Kicked, string? KickReason,
    string? ServerId, string? Error, List<string> Log);

static class LoginProbe
{
    static async Task<(int id, byte[] payload)> ReadLoginPacketAsync(
        Stream s, bool compressed, CancellationToken ct)
    {
        int len = await VarInt.ReadAsync(s, ct);
        if (len < 0 || len > 2 * 1024 * 1024) throw new InvalidDataException("bad login packet length");
        byte[] data = await McIO.ReadExactAsync(s, len, ct);

        byte[] raw;
        if (!compressed)
        {
            raw = data;
        }
        else
        {
            using var ms = new MemoryStream(data, false);
            int dlen = await VarInt.ReadAsync(ms, CancellationToken.None);
            int header = (int)ms.Position;
            byte[] rest = data[header..];
            if (dlen == 0)
            {
                raw = rest;
            }
            else
            {
                using var zs = new ZLibStream(new MemoryStream(rest, false), CompressionMode.Decompress);
                using var outMs = new MemoryStream();
                await zs.CopyToAsync(outMs, ct);
                raw = outMs.ToArray();
            }
        }

        using var rm = new MemoryStream(raw, false);
        int id = await VarInt.ReadAsync(rm, CancellationToken.None);
        int hlen = (int)rm.Position;
        return (id, raw[hlen..]);
    }

    public static async Task<JoinResult> TryJoinAsync(
        string host, int port, int protocol, string username, int timeoutMs, CancellationToken ct)
    {
        var log = new List<string>();
        string name = new string(username.Where(c => char.IsLetterOrDigit(c) || c == '_').ToArray());
        if (name.Length is < 3 or > 16) name = "ProtoBot";

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(timeoutMs, 1) * 3));
        var token = cts.Token;

        TcpClient client;
        try { client = await McIO.ConnectAsync(host, port, timeoutMs, token); }
        catch (Exception ex) { return new JoinResult(false, false, false, null, null, "connect: " + ex.Message, log); }

        using (client)
        using (var stream = client.GetStream())
        {
            try
            {
                // handshake (next_state = 2 login)
                byte[] hs;
                using (var ms = new MemoryStream())
                {
                    VarInt.Write(ms, 0);
                    VarInt.Write(ms, protocol);
                    McIO.WriteString(ms, host);
                    McIO.WriteUShortBE(ms, (ushort)port);
                    VarInt.Write(ms, 2);
                    hs = ms.ToArray();
                }
                await McIO.SendFramedAsync(stream, hs, token);

                // login start: name + hasUUID=false (framing makes the extra byte harmless on old servers)
                byte[] ls;
                using (var ms = new MemoryStream())
                {
                    VarInt.Write(ms, 0);
                    McIO.WriteString(ms, name);
                    ms.WriteByte(0);
                    ls = ms.ToArray();
                }
                await McIO.SendFramedAsync(stream, ls, token);
                log.Add("sent Login Start as " + name);

                bool compressed = false;
                for (int i = 0; i < 16; i++)
                {
                    var (id, payload) = await ReadLoginPacketAsync(stream, compressed, token);
                    using var pm = new MemoryStream(payload, false);
                    switch (id)
                    {
                        case 0x00: // Disconnect
                        {
                            string reason = await McIO.ReadStringAsync(pm, CancellationToken.None);
                            string flat = StatusPing.FlattenText(
                                System.Text.Json.Nodes.JsonNode.Parse(
                                    reason.StartsWith('{') ? reason : "{\"text\":" + System.Text.Json.Nodes.JsonValue.Create(reason).ToJsonString() + "}")) ?? reason;
                            log.Add("kicked");
                            return new JoinResult(false, false, true, flat.Length > 500 ? flat[..500] : flat, null, null, log);
                        }
                        case 0x01: // Encryption Request -> online-mode
                        {
                            string serverId = await McIO.ReadStringAsync(pm, CancellationToken.None);
                            log.Add("encryption requested (online-mode=true)");
                            return new JoinResult(false, true, false, null, serverId, null, log);
                        }
                        case 0x02: // Login Success
                            log.Add("login success");
                            return new JoinResult(true, false, false, null, null, null, log);
                        case 0x03: // Set Compression
                        {
                            int threshold = await VarInt.ReadAsync(pm, CancellationToken.None);
                            compressed = threshold >= 0;
                            log.Add("compression threshold=" + threshold);
                            break;
                        }
                        case 0x04: // Login Plugin Request
                        {
                            int msgId = await VarInt.ReadAsync(pm, CancellationToken.None);
                            string channel = await McIO.ReadStringAsync(pm, CancellationToken.None);
                            log.Add("plugin request on " + channel);
                            byte[] resp;
                            using (var ms = new MemoryStream())
                            {
                                VarInt.Write(ms, 0x02);
                                VarInt.Write(ms, msgId);
                                ms.WriteByte(0); // not understood
                                resp = ms.ToArray();
                            }
                            await McIO.SendFramedAsync(stream, resp, token);
                            break;
                        }
                        default:
                            log.Add($"unknown login packet 0x{id:X2}");
                            break;
                    }
                }
                return new JoinResult(false, false, false, null, null, "login stalled (no terminal packet)", log);
            }
            catch (Exception ex) when (ex is OperationCanceledException or TimeoutException)
            {
                return new JoinResult(false, false, false, null, null, "timeout", log);
            }
            catch (Exception ex)
            {
                return new JoinResult(false, false, false, null, null, "login: " + ex.Message, log);
            }
        }
    }
}

// ---------------------------------------------------------------- fingerprint
sealed record FingerprintResult(
    string Software, string Confidence, List<string> Signals);

static class Fingerprint
{
    public static FingerprintResult FromStatus(StatusInfo st, QueryInfo? q)
    {
        var signals = new List<string>();
        string soft = "Unknown";
        string conf = "low";

        string v = (st.VersionName ?? "").ToLowerInvariant();
        void Hit(string name, string why)
        {
            soft = name; conf = "high";
            signals.Add(why);
        }

        if (v.Contains("velocity")) Hit("Velocity", "version string advertises Velocity");
        else if (v.Contains("bungee") || v.Contains("waterfall")) Hit(v.Contains("waterfall") ? "Waterfall" : "BungeeCord", "version string advertises proxy");
        else if (v.Contains("paper")) Hit("Paper", "version string advertises Paper");
        else if (v.Contains("purpur")) Hit("Purpur", "version string advertises Purpur");
        else if (v.Contains("spigot")) Hit("Spigot", "version string advertises Spigot");
        else if (v.Contains("bukkit") || v.Contains("craftbukkit")) Hit("CraftBukkit", "version string advertises Bukkit");
        else if (v.Contains("fabric")) Hit("Fabric", "version string advertises Fabric");
        else if (v.Contains("forge") || v.Contains("mohist") || v.Contains("arclight")) Hit(v.Contains("mohist") ? "Mohist" : v.Contains("arclight") ? "Arclight" : "Forge", "version string advertises modded");
        else if (v.Contains("vanilla")) Hit("Vanilla", "version string advertises Vanilla");
        else if (v.Length > 0) signals.Add("opaque version string: " + st.VersionName);

        if (st.HasModInfo) { soft = "Forge/modded"; conf = "high"; signals.Add("modinfo/forgeData present"); }
        if (q is { Ok: true })
        {
            if (q.Keys.TryGetValue("gametype", out var gt)) signals.Add("query gametype=" + gt);
            if (q.Keys.TryGetValue("plugins", out var pl) && pl.Length > 0)
            {
                signals.Add("query exposes plugins: " + (pl.Length > 200 ? pl[..200] + "..." : pl));
            }
        }
        if (st.HasFavicon) signals.Add("custom favicon present");
        if (st.Online is 0 && st.Max > 0) signals.Add("server empty right now");

        return new FingerprintResult(soft, conf, signals);
    }

    public static readonly Dictionary<int, string> ProtocolToVersion = new()
    {
        [47] = "1.8-1.8.9", [107] = "1.9", [108] = "1.9.1", [109] = "1.9.2", [110] = "1.9.4",
        [210] = "1.10", [315] = "1.11", [316] = "1.11.2", [335] = "1.12", [338] = "1.12.1", [340] = "1.12.2",
        [393] = "1.13", [401] = "1.13.1", [404] = "1.13.2", [477] = "1.14", [480] = "1.14.1",
        [485] = "1.14.2", [490] = "1.14.3", [498] = "1.14.4", [573] = "1.15", [575] = "1.15.1",
        [578] = "1.15.2", [578 + 1] = "1.15.2+", [755] = "1.17", [756] = "1.17.1",
        [757] = "1.18-1.18.1", [758] = "1.18.2", [759] = "1.19", [760] = "1.19.1-2",
        [761] = "1.19.3", [762] = "1.19.4", [763] = "1.20-1.20.1", [764] = "1.20.2",
        [765] = "1.20.3-4", [766] = "1.20.5-6", [767] = "1.21-1.21.1", [768] = "1.21.2-3",
        [769] = "1.21.4", [770] = "1.21.5", [771] = "1.21.6", [772] = "1.21.7-8"
    };

    public static string VersionLabel(int protocol)
        => ProtocolToVersion.TryGetValue(protocol, out var v) ? v : "unknown";
}
