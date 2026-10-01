using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace ProtoMcp;

// ---------------------------------------------------------------- VarInt
static class VarInt
{
    public static void Write(Stream s, int value)
    {
        uint v = (uint)value;
        do
        {
            byte b = (byte)(v & 0x7F);
            v >>= 7;
            if (v != 0) b |= 0x80;
            s.WriteByte(b);
        } while (v != 0);
    }

    public static int EncodedLength(int value)
    {
        uint v = (uint)value;
        int n = 0;
        do { v >>= 7; n++; } while (v != 0);
        return n;
    }

    public static async Task<int> ReadAsync(Stream s, CancellationToken ct)
    {
        int result = 0, numRead = 0;
        var one = new byte[1];
        while (true)
        {
            await McIO.ReadExactAsync(s, one, ct);
            byte b = one[0];
            result |= (b & 0x7F) << (7 * numRead);
            numRead++;
            if (numRead > 5) throw new InvalidDataException("varint too long");
            if ((b & 0x80) == 0) break;
        }
        return result;
    }
}

// ---------------------------------------------------------------- low-level io
static class McIO
{
    public static async Task ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
        => await ReadExactAsync(s, new Memory<byte>(buf), ct);

    public static async Task ReadExactAsync(Stream s, Memory<byte> buf, CancellationToken ct)
    {
        int off = 0;
        while (off < buf.Length)
        {
            int n = await s.ReadAsync(buf.Slice(off), ct);
            if (n == 0) throw new EndOfStreamException("connection closed");
            off += n;
        }
    }

    public static async Task<byte[]> ReadExactAsync(Stream s, int n, CancellationToken ct)
    {
        var buf = new byte[n];
        await ReadExactAsync(s, buf, ct);
        return buf;
    }

    public static void WriteString(Stream s, string v)
    {
        var b = Encoding.UTF8.GetBytes(v);
        VarInt.Write(s, b.Length);
        s.Write(b, 0, b.Length);
    }

    public static async Task<string> ReadStringAsync(Stream s, CancellationToken ct, int maxBytes = 2 * 1024 * 1024)
    {
        int len = await VarInt.ReadAsync(s, ct);
        if (len < 0 || len > maxBytes) throw new InvalidDataException("bad string length");
        var b = await ReadExactAsync(s, len, ct);
        return Encoding.UTF8.GetString(b);
    }

    public static void WriteUShortBE(Stream s, ushort v)
    {
        s.WriteByte((byte)(v >> 8));
        s.WriteByte((byte)(v & 0xFF));
    }

    public static void WriteLongBE(Stream s, long v)
    {
        for (int i = 7; i >= 0; i--) s.WriteByte((byte)((v >> (8 * i)) & 0xFF));
    }

    public static async Task<long> ReadLongBEAsync(Stream s, CancellationToken ct)
    {
        var b = await ReadExactAsync(s, 8, ct);
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
        return v;
    }

    public static void WriteIntBE(Stream s, int v)
    {
        s.WriteByte((byte)((v >> 24) & 0xFF));
        s.WriteByte((byte)((v >> 16) & 0xFF));
        s.WriteByte((byte)((v >> 8) & 0xFF));
        s.WriteByte((byte)(v & 0xFF));
    }

    public static void WriteIntLE(Stream s, int v)
    {
        s.WriteByte((byte)(v & 0xFF));
        s.WriteByte((byte)((v >> 8) & 0xFF));
        s.WriteByte((byte)((v >> 16) & 0xFF));
        s.WriteByte((byte)((v >> 24) & 0xFF));
    }

    public static async Task<int> ReadIntLEAsync(Stream s, CancellationToken ct)
    {
        var b = await ReadExactAsync(s, 4, ct);
        return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
    }

    public static async Task<TcpClient> ConnectAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        var client = new TcpClient();
        try
        {
            var task = client.ConnectAsync(host, port);
            var done = await Task.WhenAny(task, Task.Delay(timeoutMs, ct));
            if (done != task) { client.Dispose(); throw new TimeoutException("connect timed out"); }
            await task;
            client.ReceiveTimeout = timeoutMs;
            client.SendTimeout = timeoutMs;
            return client;
        }
        catch { client.Dispose(); throw; }
    }

    public static async Task SendFramedAsync(Stream s, byte[] body, CancellationToken ct, bool compressed = false)
    {
        using var payload = new MemoryStream();
        if (compressed)
        {
            // varint dataLength=0 means body is below the compression threshold (uncompressed)
            VarInt.Write(payload, 0);
        }
        payload.Write(body, 0, body.Length);
        var inner = payload.ToArray();

        using var frame = new MemoryStream();
        VarInt.Write(frame, inner.Length);
        frame.Write(inner, 0, inner.Length);
        var outBuf = frame.ToArray();
        await s.WriteAsync(outBuf, ct);
        await s.FlushAsync(ct);
    }

    public static async Task<(int id, byte[] payload)> ReadPacketAsync(Stream s, CancellationToken ct, int maxLen = 4 * 1024 * 1024)
    {
        int len = await VarInt.ReadAsync(s, ct);
        if (len < 0 || len > maxLen) throw new InvalidDataException("bad packet length");
        var data = await ReadExactAsync(s, len, ct);
        using var ms = new MemoryStream(data, false);
        int id = await VarInt.ReadAsync(ms, CancellationToken.None);
        int header = (int)ms.Position;
        var payload = new byte[data.Length - header];
        Buffer.BlockCopy(data, header, payload, 0, payload.Length);
        return (id, payload);
    }
}

// ---------------------------------------------------------------- DNS SRV (minimal)
static class DnsSrv
{
    public static async Task<(string target, int port)?> LookupMinecraftSrvAsync(
        string host, int timeoutMs, CancellationToken ct)
    {
        try
        {
            string qname = "_minecraft._tcp." + host.TrimEnd('.');
            using var ms = new MemoryStream();
            ushort txid = (ushort)Random.Shared.Next(1, 65535);
            McIO.WriteUShortBE(ms, txid);
            McIO.WriteUShortBE(ms, 0x0100); // standard query, recursion desired
            McIO.WriteUShortBE(ms, 1);      // QDCOUNT
            McIO.WriteUShortBE(ms, 0);
            McIO.WriteUShortBE(ms, 0);
            McIO.WriteUShortBE(ms, 0);
            foreach (var label in qname.Split('.'))
            {
                var lb = Encoding.ASCII.GetBytes(label);
                ms.WriteByte((byte)lb.Length);
                ms.Write(lb, 0, lb.Length);
            }
            ms.WriteByte(0);
            McIO.WriteUShortBE(ms, 33); // SRV
            McIO.WriteUShortBE(ms, 1);  // IN
            var query = ms.ToArray();

            using var udp = new UdpClient();
            var dst = new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53);
            await udp.SendAsync(query, query.Length, dst);
            var t = udp.ReceiveAsync();
            var done = await Task.WhenAny(t, Task.Delay(timeoutMs, ct));
            if (done != t) return null;
            var res = await t;
            return ParseSrv(res.Buffer, txid);
        }
        catch { return null; }
    }

    private static string ReadName(byte[] b, ref int off)
    {
        var sb = new StringBuilder();
        int jumps = 0;
        while (true)
        {
            if (off >= b.Length) break;
            byte len = b[off++];
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0)
            {
                if (off >= b.Length) break;
                int ptr = ((len & 0x3F) << 8) | b[off++];
                if (++jumps > 8) break;
                int save = off;
                off = ptr;
                string rest = ReadName(b, ref off);
                if (sb.Length > 0 && rest.Length > 0) sb.Append('.');
                sb.Append(rest);
                off = save;
                break;
            }
            if (off + len > b.Length) break;
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(b, off, len));
            off += len;
        }
        return sb.ToString();
    }

    private static (string target, int port)? ParseSrv(byte[] b, ushort txid)
    {
        if (b.Length < 12) return null;
        int off = 0;
        ushort id = (ushort)((b[0] << 8) | b[1]);
        if (id != txid) return null;
        ushort flags = (ushort)((b[2] << 8) | b[3]);
        if ((flags & 0x8000) == 0) return null;
        ushort qd = (ushort)((b[4] << 8) | b[5]);
        ushort an = (ushort)((b[6] << 8) | b[7]);
        off = 12;
        for (int i = 0; i < qd; i++)
        {
            ReadName(b, ref off);
            off += 4;
        }
        for (int i = 0; i < an; i++)
        {
            ReadName(b, ref off);
            if (off + 10 > b.Length) return null;
            ushort type = (ushort)((b[off] << 8) | b[off + 1]);
            // ushort cls = ...
            // uint ttl = ...
            ushort rdlen = (ushort)((b[off + 8] << 8) | b[off + 9]);
            off += 10;
            if (type == 33 && off + rdlen <= b.Length && rdlen >= 6)
            {
                // ushort prio = (b[off]<<8)|b[off+1]; weight...
                int port = (b[off + 4] << 8) | b[off + 5];
                int toff = off + 6;
                string target = ReadName(b, ref toff).TrimEnd('.');
                if (!string.IsNullOrEmpty(target) && target != ".") return (target, port);
            }
            off += rdlen;
        }
        return null;
    }
}

// ---------------------------------------------------------------- status ping
sealed record StatusInfo(
    bool Ok, string? Error, string? Json, string? VersionName, int Protocol,
    int? Online, int? Max, string? Motd, bool HasFavicon, bool HasModInfo, long LatencyMs);

static class StatusPing
{
    public static async Task<StatusInfo> PingAsync(
        string host, int port, int protocol, int timeoutMs, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(timeoutMs, 1) * 4));
        var token = cts.Token;

        TcpClient client;
        try { client = await McIO.ConnectAsync(host, port, timeoutMs, token); }
        catch (Exception ex) { return new StatusInfo(false, "connect: " + ex.Message, null, null, 0, null, null, null, false, false, 0); }
        using (client)
        using (var stream = client.GetStream())
        {
            try
            {
                // handshake (next_state = 1 status)
                byte[] hs;
                using (var ms = new MemoryStream())
                {
                    VarInt.Write(ms, 0);
                    VarInt.Write(ms, protocol);
                    McIO.WriteString(ms, host);
                    McIO.WriteUShortBE(ms, (ushort)port);
                    VarInt.Write(ms, 1);
                    hs = ms.ToArray();
                }
                await McIO.SendFramedAsync(stream, hs, token);

                // status request
                await McIO.SendFramedAsync(stream, new byte[] { 0x00 }, token);

                var (rid, payload) = await McIO.ReadPacketAsync(stream, token);
                if (rid != 0x00) return new StatusInfo(false, "unexpected status packet id " + rid, null, null, 0, null, null, null, false, false, 0);
                string json;
                using (var ms = new MemoryStream(payload, false)) json = await McIO.ReadStringAsync(ms, CancellationToken.None);

                // ping/pong for latency
                long t0 = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                byte[] ping;
                using (var ms = new MemoryStream()) { VarInt.Write(ms, 1); McIO.WriteLongBE(ms, t0); ping = ms.ToArray(); }
                await McIO.SendFramedAsync(stream, ping, token);
                try
                {
                    var (pid, _) = await McIO.ReadPacketAsync(stream, token);
                    if (pid != 1) { /* ignore */ }
                }
                catch { /* latency optional */ }
                long latency = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - t0;

                return Parse(json, latency);
            }
            catch (Exception ex) when (ex is OperationCanceledException or TimeoutException)
            {
                return new StatusInfo(false, "timeout", null, null, 0, null, null, null, false, false, 0);
            }
            catch (Exception ex)
            {
                return new StatusInfo(false, "protocol: " + ex.Message, null, null, 0, null, null, null, false, false, 0);
            }
        }
    }

    private static StatusInfo Parse(string json, long latency)
    {
        try
        {
            var node = JsonNode.Parse(json)?.AsObject();
            if (node is null) return new StatusInfo(false, "bad status json", json, null, 0, null, null, null, false, false, latency);

            var ver = node["version"]?.AsObject();
            string? vname = ver?["name"]?.GetValue<string>();
            int proto = ver?["protocol"]?.GetValue<int>() ?? 0;

            var pl = node["players"]?.AsObject();
            int? online = pl?["online"]?.GetValue<int>();
            int? max = pl?["max"]?.GetValue<int>();

            string? motd = FlattenText(node["description"]);
            bool fav = node["favicon"]?.GetValue<string>() is string f && f.StartsWith("data:image/png;base64,");
            bool mod = node["modinfo"] is not null || node["forgeData"] is not null;

            return new StatusInfo(true, null, json, vname, proto, online, max, motd, fav, mod, latency);
        }
        catch (Exception ex)
        {
            return new StatusInfo(false, "parse: " + ex.Message, json, null, 0, null, null, null, false, false, latency);
        }
    }

    public static string? FlattenText(JsonNode? n)
    {
        if (n is null) return null;
        try
        {
            if (n is JsonValue v)
            {
                if (v.TryGetValue<string>(out var s)) return s;
                return v.ToString();
            }
            if (n is JsonObject o)
            {
                var sb = new StringBuilder();
                if (o["text"]?.GetValue<string>() is string t) sb.Append(t);
                if (o["extra"] is JsonArray arr) foreach (var e in arr) sb.Append(FlattenText(e));
                return sb.ToString();
            }
            if (n is JsonArray a)
            {
                var sb = new StringBuilder();
                foreach (var e in a) sb.Append(FlattenText(e));
                return sb.ToString();
            }
        }
        catch { }
        return null;
    }
}

// ---------------------------------------------------------------- GameSpy4 query (UDP)
sealed record QueryInfo(
    bool Ok, string? Error, Dictionary<string, string> Keys, List<string> Players, bool Full);

static class GameSpyQuery
{
    public static async Task<QueryInfo> QueryAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        using var udp = new UdpClient();
        try
        {
            IPAddress ip;
            try { ip = (await Dns.GetHostAddressesAsync(host))[0]; }
            catch (Exception ex) { return new QueryInfo(false, "dns: " + ex.Message, new(), new(), false); }

            var ep = new IPEndPoint(ip, port);
            int session = Random.Shared.Next(1, int.MaxValue);

            // challenge
            byte[] chal;
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0xFE); ms.WriteByte(0xFD); ms.WriteByte(0x09);
                McIO.WriteIntBE(ms, session);
                chal = ms.ToArray();
            }
            await udp.SendAsync(chal, chal.Length, ep);
            var r1 = await RecvAsync(udp, timeoutMs, ct);
            int challenge = ParseChallenge(r1.Buffer, session);
            if (challenge == 0) return new QueryInfo(false, "bad challenge response", new(), new(), false);

            // full stat attempt (01 02 03 00 suffix); falls back to basic parse
            byte[] stat;
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0xFE); ms.WriteByte(0xFD); ms.WriteByte(0x00);
                McIO.WriteIntBE(ms, session);
                McIO.WriteIntBE(ms, challenge);
                ms.Write(new byte[] { 0x01, 0x02, 0x03, 0x00 }, 0, 4);
                stat = ms.ToArray();
            }
            await udp.SendAsync(stat, stat.Length, ep);
            var r2 = await RecvAsync(udp, timeoutMs, ct);
            return ParseStat(r2.Buffer, session);
        }
        catch (Exception ex) when (ex is OperationCanceledException or TimeoutException or SocketException)
        {
            return new QueryInfo(false, "query unreachable (" + ex.GetType().Name + ")", new(), new(), false);
        }
        catch (Exception ex)
        {
            return new QueryInfo(false, "query: " + ex.Message, new(), new(), false);
        }
    }

    static async Task<UdpReceiveResult> RecvAsync(UdpClient udp, int timeoutMs, CancellationToken ct)
    {
        var t = udp.ReceiveAsync();
        var done = await Task.WhenAny(t, Task.Delay(timeoutMs, ct));
        if (done != t) throw new TimeoutException("udp receive timeout");
        return await t;
    }

    private static int ParseChallenge(byte[] b, int session)
    {
        // 09 <session:4BE> <ascii digits> 00
        if (b.Length < 5 || b[0] != 0x09) return 0;
        int s = (b[1] << 24) | (b[2] << 16) | (b[3] << 8) | b[4];
        if (s != session) return 0;
        string digits = Encoding.ASCII.GetString(b, 5, b.Length - 5).Trim('\0', ' ', '\r', '\n');
        return int.TryParse(digits, out int c) ? c : 0;
    }

    private static QueryInfo ParseStat(byte[] b, int session)
    {
        // 00 <session:4BE> payload...
        if (b.Length < 5 || b[0] != 0x00) return new QueryInfo(false, "bad stat header", new(), new(), false);
        string s = Encoding.Latin1.GetString(b, 5, b.Length - 5);
        var parts = s.Split('\0');
        var keys = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var players = new List<string>();
        int i = 0;
        // skip leading empties
        while (i < parts.Length && parts[i].Length == 0) i++;
        // walk key/value pairs until player_ marker or end
        for (; i + 1 < parts.Length; i += 2)
        {
            string k = parts[i].Trim();
            if (k.Length == 0) { i--; continue; }
            if (k.Equals("player_", StringComparison.OrdinalIgnoreCase))
            {
                i++;
                // skip empties then collect players
                while (i < parts.Length && parts[i].Length == 0) i++;
                for (; i < parts.Length; i++)
                    if (parts[i].Length > 0) players.Add(parts[i]);
                break;
            }
            keys[k] = parts[i + 1];
        }
        bool full = keys.ContainsKey("plugins") || keys.ContainsKey("plugin");
        return new QueryInfo(true, null, keys, players, full);
    }
}
