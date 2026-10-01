using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace ProtoMcp;

static class McTools
{
    public static void RegisterAll()
    {
        McpServer.Add("mc_resolve",
            "Resolve a Minecraft host: IPs, SRV _minecraft._tcp, and TCP port checks.",
            """
            {"type":"object","properties":{
              "host":{"type":"string","description":"hostname or IP (no port)"}
            },"required":["host"]}
            """,
            async (a, ct) =>
            {
                string host = Str(a, "host", "");
                if (host.Length == 0) return McpServer.Fail("host required");
                var j = await ResolveAsync(host, ct);
                return McpServer.Ok(j);
            });

        McpServer.Add("mc_ping",
            "Server List Ping: version, protocol, MOTD, players, latency.",
            """
            {"type":"object","properties":{
              "host":{"type":"string"},"port":{"type":"integer","default":25565},
              "protocol":{"type":"integer","default":763},
              "timeout_ms":{"type":"integer","default":5000}
            },"required":["host"]}
            """,
            async (a, ct) =>
            {
                string host = Str(a, "host", "");
                int port = Int(a, "port", 25565);
                int proto = Int(a, "protocol", 763);
                int to = Int(a, "timeout_ms", 5000);
                var st = await StatusPing.PingAsync(host, port, proto, to, ct);
                var j = new JsonObject
                {
                    ["ok"] = st.Ok, ["host"] = host, ["port"] = port,
                    ["latency_ms"] = st.LatencyMs
                };
                if (!st.Ok) j["error"] = st.Error;
                else
                {
                    j["version"] = st.VersionName; j["protocol"] = st.Protocol;
                    j["version_label"] = Fingerprint.VersionLabel(st.Protocol);
                    if (st.Online is not null) j["online"] = st.Online;
                    if (st.Max is not null) j["max"] = st.Max;
                    if (st.Motd is not null) j["motd"] = st.Motd;
                    j["has_favicon"] = st.HasFavicon; j["has_modinfo"] = st.HasModInfo;
                }
                return McpServer.Ok(j);
            });

        McpServer.Add("mc_fingerprint",
            "Guess server software (Paper/Purpur/Spigot/Velocity/Bungee/Vanilla/Forge) from the ping response.",
            """
            {"type":"object","properties":{
              "host":{"type":"string"},"port":{"type":"integer","default":25565},
              "timeout_ms":{"type":"integer","default":5000}
            },"required":["host"]}
            """,
            async (a, ct) =>
            {
                string host = Str(a, "host", "");
                int port = Int(a, "port", 25565);
                int to = Int(a, "timeout_ms", 5000);
                var st = await StatusPing.PingAsync(host, port, 763, to, ct);
                if (!st.Ok) return McpServer.Fail(st.Error ?? "ping failed");
                QueryInfo? q = null;
                try { q = await GameSpyQuery.QueryAsync(host, port, Math.Min(to, 3000), ct); } catch { }
                var fp = Fingerprint.FromStatus(st, q?.Ok == true ? q : null);
                var j = new JsonObject
                {
                    ["software"] = fp.Software, ["confidence"] = fp.Confidence,
                    ["version"] = st.VersionName, ["protocol"] = st.Protocol,
                    ["version_label"] = Fingerprint.VersionLabel(st.Protocol)
                };
                var arr = new JsonArray();
                foreach (var s in fp.Signals) arr.Add(s);
                j["signals"] = arr;
                return McpServer.Ok(j);
            });

        McpServer.Add("mc_query",
            "GameSpy4 UDP query: server keys, and plugin/player lists when exposed.",
            """
            {"type":"object","properties":{
              "host":{"type":"string"},"port":{"type":"integer","default":25565},
              "timeout_ms":{"type":"integer","default":3000}
            },"required":["host"]}
            """,
            async (a, ct) =>
            {
                var q = await GameSpyQuery.QueryAsync(Str(a, "host", ""), Int(a, "port", 25565), Int(a, "timeout_ms", 3000), ct);
                var j = new JsonObject { ["ok"] = q.Ok, ["full"] = q.Full };
                if (!q.Ok) j["error"] = q.Error;
                else
                {
                    var keys = new JsonObject();
                    foreach (var kv in q.Keys) keys[kv.Key] = kv.Value;
                    j["keys"] = keys;
                    var pl = new JsonArray();
                    foreach (var p in q.Players) pl.Add(p);
                    j["players"] = pl;
                }
                return McpServer.Ok(j);
            });

        McpServer.Add("mc_rcon_probe",
            "Check if RCON is exposed: single empty-password auth attempt (detection only, no brute force).",
            """
            {"type":"object","properties":{
              "host":{"type":"string"},"port":{"type":"integer","default":25575},
              "timeout_ms":{"type":"integer","default":5000}
            },"required":["host"]}
            """,
            async (a, ct) =>
            {
                var r = await Rcon.ProbeAsync(Str(a, "host", ""), Int(a, "port", 25575), Int(a, "timeout_ms", 5000), ct);
                var j = new JsonObject
                {
                    ["tcp_open"] = r.TcpOpen, ["authed_empty"] = r.Authed,
                    ["exposed"] = r.TcpOpen
                };
                if (r.Error is not null) j["error"] = r.Error;
                var log = new JsonArray();
                foreach (var l in r.Log) log.Add(l);
                j["log"] = log;
                return McpServer.Ok(j);
            });

        McpServer.Add("mc_rcon_brute",
            "Try an explicit password list against RCON. Requires user-supplied passwords; capped at 100 attempts.",
            """
            {"type":"object","properties":{
              "host":{"type":"string"},"port":{"type":"integer","default":25575},
              "passwords":{"type":"array","items":{"type":"string"}},
              "delay_ms":{"type":"integer","default":500},
              "timeout_ms":{"type":"integer","default":5000}
            },"required":["host","passwords"]}
            """,
            async (a, ct) =>
            {
                var pws = new List<string>();
                if (a["passwords"] is JsonArray arr) foreach (var p in arr)
                    { try { if (p?.GetValue<string>() is string s) pws.Add(s); } catch { } }
                if (pws.Count == 0) return McpServer.Fail("passwords required");
                var (ok, tried, err) = await Rcon.BruteAsync(
                    Str(a, "host", ""), Int(a, "port", 25575), pws.ToArray(),
                    Int(a, "delay_ms", 500), Int(a, "timeout_ms", 5000), ct);
                var j = new JsonObject { ["ok"] = ok, ["attempts"] = tried.Count };
                if (ok) j["password"] = tried[^1];
                if (err is not null) j["error"] = err;
                return McpServer.Ok(j);
            });

        McpServer.Add("mc_join",
            "Attempt an offline-mode login as a bot. Reports JOIN / online-mode-required / kick reason.",
            """
            {"type":"object","properties":{
              "host":{"type":"string"},"port":{"type":"integer","default":25565},
              "username":{"type":"string","default":"ProtoBot"},
              "protocol":{"type":"integer","default":0},
              "timeout_ms":{"type":"integer","default":8000}
            },"required":["host"]}
            """,
            async (a, ct) =>
            {
                string host = Str(a, "host", "");
                int port = Int(a, "port", 25565);
                int proto = Int(a, "protocol", 0);
                if (proto == 0)
                {
                    try
                    {
                        var st = await StatusPing.PingAsync(host, port, 763, 4000, ct);
                        if (st.Ok && st.Protocol > 0) proto = st.Protocol;
                    }
                    catch { }
                    if (proto == 0) proto = 763;
                }
                var r = await LoginProbe.TryJoinAsync(host, port, proto, Str(a, "username", "ProtoBot"), Int(a, "timeout_ms", 8000), ct);
                var j = new JsonObject
                {
                    ["joined"] = r.Joined, ["online_mode_required"] = r.OnlineModeRequired,
                    ["kicked"] = r.Kicked, ["protocol_used"] = proto
                };
                if (r.KickReason is not null) j["kick_reason"] = r.KickReason;
                if (r.ServerId is not null) j["server_id"] = r.ServerId;
                if (r.Error is not null) j["error"] = r.Error;
                var log = new JsonArray();
                foreach (var l in r.Log) log.Add(l);
                j["log"] = log;
                return McpServer.Ok(j);
            });

        McpServer.Add("mc_sit",
            "Join the server and keep the player online for N seconds, logging play packets.",
            """
            {"type":"object","properties":{
              "host":{"type":"string"},"port":{"type":"integer","default":25565},
              "username":{"type":"string","default":"ProtoBot"},
              "protocol":{"type":"integer","default":0},
              "hold_seconds":{"type":"integer","default":20},
              "timeout_ms":{"type":"integer","default":10000}
            },"required":["host"]}
            """,
            async (a, ct) =>
            {
                string host = Str(a, "host", "");
                int port = Int(a, "port", 25565);
                int proto = Int(a, "protocol", 0);
                if (proto == 0)
                {
                    try
                    {
                        var st = await StatusPing.PingAsync(host, port, 763, 4000, ct);
                        if (st.Ok && st.Protocol > 0) proto = st.Protocol;
                    }
                    catch { }
                    if (proto == 0) proto = 763;
                }
                int hold = Int(a, "hold_seconds", 20);
                var r = await LoginProbe.TryJoinAsync(host, port, proto, Str(a, "username", "ProtoBot"),
                    Int(a, "timeout_ms", 10000), ct, holdSeconds: hold);
                var j = new JsonObject
                {
                    ["joined"] = r.Joined, ["online_mode_required"] = r.OnlineModeRequired,
                    ["hold_seconds"] = hold, ["protocol_used"] = proto
                };
                if (r.KickReason is not null) j["kick_reason"] = r.KickReason;
                if (r.Error is not null) j["error"] = r.Error;
                var log = new JsonArray();
                foreach (var l in r.Log) log.Add(l);
                j["log"] = log;
                return McpServer.Ok(j);
            });

        McpServer.Add("mc_say",
            "Join the server, send a chat message, then disconnect.",
            """
            {"type":"object","properties":{
              "host":{"type":"string"},"port":{"type":"integer","default":25565},
              "username":{"type":"string","default":"ProtoBot"},
              "message":{"type":"string","default":"hola"},
              "protocol":{"type":"integer","default":0},
              "timeout_ms":{"type":"integer","default":10000}
            },"required":["host"]}
            """,
            async (a, ct) =>
            {
                string host = Str(a, "host", "");
                int port = Int(a, "port", 25565);
                int proto = Int(a, "protocol", 0);
                string msg = Str(a, "message", "hola");
                string user = Str(a, "username", "ProtoBot");

                if (proto == 0)
                {
                    try
                    {
                        var st = await StatusPing.PingAsync(host, port, 763, 4000, ct);
                        if (st.Ok && st.Protocol > 0) proto = st.Protocol;
                    }
                    catch { }
                    if (proto == 0) proto = 763;
                }

                var log = new List<string>();
                string name = new string(user.Where(c => char.IsLetterOrDigit(c) || c == '_').ToArray());
                if (name.Length is < 3 or > 16) name = "ProtoBot";

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(Int(a, "timeout_ms", 10000), 1) * 3));
                var token = cts.Token;

                TcpClient client;
                try { client = await McIO.ConnectAsync(host, port, Int(a, "timeout_ms", 10000), token); }
                catch (Exception ex) { return McpServer.Fail("connect: " + ex.Message); }

                using (client)
                using (var stream = client.GetStream())
                {
                    try
                    {
                        // handshake login
                        byte[] hs;
                        using (var ms = new MemoryStream())
                        {
                            VarInt.Write(ms, 0); VarInt.Write(ms, proto);
                            McIO.WriteString(ms, host); McIO.WriteUShortBE(ms, (ushort)port);
                            VarInt.Write(ms, 2);
                            hs = ms.ToArray();
                        }
                        await McIO.SendFramedAsync(stream, hs, token);

                        byte[] ls;
                        using (var ms = new MemoryStream())
                        {
                            VarInt.Write(ms, 0); McIO.WriteString(ms, name);
                            ls = ms.ToArray();
                        }
                        await McIO.SendFramedAsync(stream, ls, token);
                        log.Add("sent Login Start as " + name);

                        bool compressed = false;
                        for (int i = 0; i < 16; i++)
                        {
                            var (id, payload) = await LoginProbe.ReadLoginPacketAsync(stream, compressed, token);
                            using var pm = new MemoryStream(payload, false);
                            switch (id)
                            {
                                case 0x00:
                                    return McpServer.Fail("Disconnected: " + (await McIO.ReadStringAsync(pm, CancellationToken.None)));
                                case 0x01:
                                    return McpServer.Fail("Online-mode required (Encryption Request)");
                                case 0x03:
                                    int threshold = await VarInt.ReadAsync(pm, CancellationToken.None);
                                    compressed = threshold >= 0;
                                    log.Add("compression=" + compressed);
                                    break;
                                case 0x02: // Login Success
                                    // send ChatMessage (serverbound 0x04) while in play state
                                    byte[] chat;
                                    using (var m2 = new MemoryStream())
                                    {
                                        VarInt.Write(m2, 0x04);
                                        McIO.WriteString(m2, msg);
                                        chat = m2.ToArray();
                                    }
                                    await McIO.SendFramedAsync(stream, chat, token, compressed: true);
                                    log.Add("chat sent: " + msg);
                                    // brief pause so the server can process, then let the using() close disconnect
                                    await Task.Delay(500, token);
                                    var j = new JsonObject
                                    {
                                        ["sent"] = true, ["message"] = msg,
                                        ["username"] = name, ["protocol"] = proto
                                    };
                                    var logArr = new JsonArray();
                                    foreach (var l in log) logArr.Add(l);
                                    j["log"] = logArr;
                                    return McpServer.Ok(j);
                                case 0x04: break;
                                default: break;
                            }
                        }
                        return McpServer.Fail("login stalled");
                    }
                    catch (Exception ex) { return McpServer.Fail("mc_say: " + ex.Message); }
                }
            });

        McpServer.Add("mc_auto",
            "Full recon pipeline from just host[:port]: resolve -> ping -> fingerprint -> query -> rcon probe -> join attempt. Returns an access assessment.",
            """
            {"type":"object","properties":{
              "target":{"type":"string","description":"host, host:port, or IP:port"},
              "username":{"type":"string","default":"ProtoBot"},
              "rcon_port":{"type":"integer","description":"explicit RCON port (default 25575)","default":25575},
              "timeout_ms":{"type":"integer","default":6000}
            },"required":["target"]}
            """,
            async (a, ct) => await AutoHackAsync(
                Str(a, "target", ""), Str(a, "username", "ProtoBot"), Int(a, "rcon_port", 25575), Int(a, "timeout_ms", 6000), ct));

        McpServer.Add("sys_selftest",
            "Offline self-test: VarInt roundtrip, packet framing, and error handling (no network).",
            """{"type":"object","properties":{}}""",
            (_, _) =>
            {
                var j = SelfTest();
                return Task.FromResult(McpServer.Ok(j));
            });
    }

    // ------------------------------------------------------------ helpers
    static string Str(JsonObject a, string k, string dflt)
    {
        try { return a[k]?.GetValue<string>() ?? dflt; } catch { return dflt; }
    }

    static int Int(JsonObject a, string k, int dflt)
    {
        try
        {
            var n = a[k];
            if (n is null) return dflt;
            if (n is JsonValue v)
            {
                if (v.TryGetValue<int>(out var i)) return i;
                if (v.TryGetValue<long>(out var l)) return (int)l;
                if (v.TryGetValue<string>(out var s) && int.TryParse(s, out var p)) return p;
            }
            return dflt;
        }
        catch { return dflt; }
    }

    static (string host, int port) ParseTarget(string target)
    {
        target = target.Trim();
        int port = 25565;
        string host = target;
        int colon = target.LastIndexOf(':');
        // host:port (but not bare IPv6)
        if (colon > 0 && target.IndexOf(':') == colon && int.TryParse(target[(colon + 1)..], out int p))
        {
            host = target[..colon];
            port = p;
        }
        return (host, port);
    }

    static async Task<bool> TcpOpenAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var c = await McIO.ConnectAsync(host, port, timeoutMs, ct);
            return true;
        }
        catch { return false; }
    }

    static async Task<JsonObject> ResolveAsync(string host, CancellationToken ct)
    {
        var j = new JsonObject { ["host"] = host };
        var ips = new JsonArray();
        try
        {
            var entry = await Dns.GetHostEntryAsync(host);
            foreach (var ip in entry.AddressList) ips.Add(ip.ToString());
        }
        catch (Exception ex) { j["dns_error"] = ex.Message; }
        j["addresses"] = ips;

        try
        {
            var srv = await DnsSrv.LookupMinecraftSrvAsync(host, 3000, ct);
            if (srv is not null)
            {
                j["srv_target"] = srv.Value.target;
                j["srv_port"] = srv.Value.port;
            }
        }
        catch { }

        var ports = new JsonObject();
        foreach (int p in new[] { 25565, 25575 })
        {
            bool open = await TcpOpenAsync(host, p, 2000, ct);
            ports[p.ToString()] = open ? "open" : "closed";
        }
        j["tcp"] = ports;
        return j;
    }

    // ------------------------------------------------------------ auto pipeline
    static async Task<ToolResult> AutoHackAsync(string target, string username, int rconPort, int timeoutMs, CancellationToken ct)
    {
        if (target.Length == 0) return McpServer.Fail("target required");
        var (host, port) = ParseTarget(target);

        var report = new JsonObject { ["target"] = target, ["host"] = host, ["port"] = port };
        var evidence = new JsonArray();
        void Ev(string s) => evidence.Add(s);

        // 1. resolve (+ SRV may redirect port)
        JsonObject res;
        try { res = await ResolveAsync(host, ct); }
        catch (Exception ex) { return McpServer.Fail("resolve: " + ex.Message); }
        report["resolve"] = res.DeepClone();
        if (res["srv_port"]?.GetValue<int>() is int srvPort && srvPort is > 0 and < 65536)
        {
            port = srvPort;
            report["port"] = port;
            Ev($"SRV redirects to port {port}");
        }

        // 2. ping
        var st = await StatusPing.PingAsync(host, port, 763, timeoutMs, ct);
        if (!st.Ok)
        {
            report["level"] = "UNREACHABLE";
            report["error"] = st.Error;
            report["evidence"] = evidence;
            report["recommendation"] = "No MC handshake response. Verify host/port, or the server uses a non-standard port / whitelist at proxy level.";
            return McpServer.Ok(report);
        }
        report["ping"] = new JsonObject
        {
            ["version"] = st.VersionName, ["protocol"] = st.Protocol,
            ["version_label"] = Fingerprint.VersionLabel(st.Protocol),
            ["online"] = st.Online, ["max"] = st.Max,
            ["motd"] = st.Motd, ["latency_ms"] = st.LatencyMs
        };
        Ev($"online: {st.VersionName} (proto {st.Protocol}), {st.Online}/{st.Max} players, {st.LatencyMs}ms");

        // 3. fingerprint
        QueryInfo? q = null;
        try { q = await GameSpyQuery.QueryAsync(host, port, Math.Min(timeoutMs, 3000), ct); } catch { }
        var fp = Fingerprint.FromStatus(st, q?.Ok == true ? q : null);
        report["fingerprint"] = new JsonObject
        {
            ["software"] = fp.Software, ["confidence"] = fp.Confidence,
            ["signals"] = new JsonArray(fp.Signals.Select(s => (JsonNode)s).ToArray())
        };
        Ev($"software guess: {fp.Software} ({fp.Confidence})");

        // 4. query exposure
        if (q?.Ok == true)
        {
            var qj = new JsonObject { ["full"] = q.Full };
            var keys = new JsonObject();
            foreach (var kv in q.Keys) keys[kv.Key] = kv.Value.Length > 300 ? kv.Value[..300] : kv.Value;
            qj["keys"] = keys;
            report["query"] = qj;
            Ev(q.Full ? "GameSpy query FULL exposed (may leak plugins)" : "GameSpy query basic exposed");
        }
        else Ev("GameSpy query closed/filtered");

        // 5. rcon probe (default 25575, plus the game port just in case).
        // Only counts when the peer actually speaks RCON (auth accept or explicit reject);
        // a bare TCP open on the game port is NOT RCON.
        RconResult? rcon = null;
        foreach (int rp in new[] { rconPort, 25575, port }.Distinct())
        {
            try
            {
                var r = await Rcon.ProbeAsync(host, rp, Math.Min(timeoutMs, 5000), ct);
                if (r.Authed || r.Error == "auth rejected by RCON server")
                {
                    rcon = r;
                    report["rcon_port"] = rp;
                    break;
                }
            }
            catch { }
        }
        if (rcon is not null)
        {
            report["rcon"] = new JsonObject
            {
                ["open"] = true, ["empty_password_works"] = rcon.Authed,
                ["note"] = rcon.Error
            };
            Ev(rcon.Authed ? "RCON OPEN WITH EMPTY PASSWORD (= instant console)" : "RCON confirmed, auth required");
        }
        else Ev("RCON not exposed (no RCON response on 25575/game port)");

        // 6. offline join attempt
        JoinResult? join = null;
        try
        {
            join = await LoginProbe.TryJoinAsync(host, port, st.Protocol > 0 ? st.Protocol : 763,
                username, Math.Max(timeoutMs, 8000), ct);
            var jj = new JsonObject
            {
                ["joined"] = join.Joined, ["online_mode_required"] = join.OnlineModeRequired,
                ["kicked"] = join.Kicked
            };
            if (join.KickReason is not null) jj["kick_reason"] = join.KickReason;
            if (join.Error is not null) jj["error"] = join.Error;
            report["join"] = jj;
            if (join.Joined) Ev($"JOINED as {username} (offline-mode or proxy misconfigured)");
            else if (join.OnlineModeRequired) Ev("online-mode=true (Mojang auth enforced)");
            else if (join.Kicked) Ev("kicked: " + (join.KickReason ?? "?")?.Substring(0, Math.Min(120, (join.KickReason ?? "?").Length)));
            else Ev("join failed: " + join.Error);
        }
        catch (Exception ex) { Ev("join error: " + ex.Message); }

        // 7. verdict
        string level, rec;
        if (rcon?.Authed == true) { level = "RCE"; rec = "RCON accepts empty password: run mc_rcon_brute only if needed, then mc console commands via RCON exec."; }
        else if (join?.Joined == true) { level = "JOIN"; rec = "Offline join works: enumerate plugins (tab-complete/help errors), then test permission abuse (/op, /pex, //calc, signs, books). Next: mc session tools."; }
        else if (rcon is not null) { level = "RCON_EXPOSED"; rec = "RCON is reachable but needs a password. mc_rcon_brute with a targeted wordlist is the next step."; }
        else if (q?.Ok == true && q.Full) { level = "INFO_PLUS"; rec = "Query leaks server internals. Use exposed plugin names to match known vulnerable versions."; }
        else if (join?.OnlineModeRequired == true) { level = "PROTECTED"; rec = "Online-mode enforced and no RCON/query exposure. Realistic paths: proxy/backend misconfig (forward spoof), plugin CVEs after joining legitimately, or DoS only."; }
        else { level = "INFO"; rec = "Reachable MC server with no trivial entry. Join legitimately or move to packet fuzzing for netcode bugs."; }

        report["level"] = level;
        report["recommendation"] = rec;
        report["evidence"] = evidence;
        return McpServer.Ok(report);
    }

    // ------------------------------------------------------------ self-test
    static JsonObject SelfTest()
    {
        var checks = new JsonArray();
        void Check(string name, bool pass, string detail)
            => checks.Add(new JsonObject { ["name"] = name, ["pass"] = pass, ["detail"] = detail });

        int[] vals = { 0, 1, 127, 128, 255, 2147483647, -1, -2147483648, 763, 47 };
        bool varintOk = true;
        foreach (int v in vals)
        {
            using var ms = new MemoryStream();
            VarInt.Write(ms, v);
            ms.Position = 0;
            int back = VarInt.ReadAsync(ms, CancellationToken.None).GetAwaiter().GetResult();
            if (back != v) { varintOk = false; break; }
        }
        Check("varint_roundtrip", varintOk, vals.Length + " values incl. negatives and protocol ids");

        bool frameOk;
        try
        {
            using var body = new MemoryStream();
            VarInt.Write(body, 0);
            VarInt.Write(body, 763);
            McIO.WriteString(body, "localhost");
            McIO.WriteUShortBE(body, 25565);
            VarInt.Write(body, 1);
            byte[] framed;
            using (var f = new MemoryStream())
            {
                VarInt.Write(f, (int)body.Length);
                body.Position = 0;
                body.CopyTo(f);
                framed = f.ToArray();
            }
            using var r = new MemoryStream(framed, false);
            int len = VarInt.ReadAsync(r, CancellationToken.None).GetAwaiter().GetResult();
            var (id, payload) = McIO.ReadPacketAsync(new MemoryStream(framed, false), CancellationToken.None).GetAwaiter().GetResult();
            frameOk = id == 0 && payload.Length == len - VarInt.EncodedLength(0);
        }
        catch (Exception ex) { frameOk = false; Check("packet_framing", false, ex.Message); return new JsonObject { ["checks"] = checks }; }
        Check("packet_framing", frameOk, "handshake body survives length-prefix roundtrip");

        // error path: connect to a closed port must fail cleanly
        bool errOk;
        try
        {
            using var c = McIO.ConnectAsync("127.0.0.1", 1, 800, CancellationToken.None).GetAwaiter().GetResult();
            errOk = false;
            c.Dispose();
        }
        catch { errOk = true; }
        Check("connect_refused_handled", errOk, "closed port returns error, not a hang");

        return new JsonObject { ["checks"] = checks };
    }
}
