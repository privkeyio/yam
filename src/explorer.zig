// Explorer.zig - Interactive network exploration mode
// Named after reconnaissance officers coordinating multiple scouts

const std = @import("std");
const yam = @import("root.zig");
const scout = @import("scout.zig");

const MAX_CONNECTIONS = 256;

pub const ConnectionState = enum { connecting, handshaking, connected };

pub const Connection = struct {
    socket: std.posix.socket_t,
    peer: yam.PeerInfo,
    state: ConnectionState,
    streaming: bool,
    handshake_state: HandshakeState,

    const HandshakeState = struct {
        received_version: bool = false,
        received_verack: bool = false,
        sent_verack: bool = false,
    };
};

pub const ManagerCommand = union(enum) {
    connect: yam.PeerInfo,
    disconnect: std.posix.socket_t,
    set_streaming: struct { socket: std.posix.socket_t, enabled: bool },
    send_getaddr: std.posix.socket_t,
};

/// Graph edge: source told us about node
pub const Edge = struct {
    source: []const u8, // "dns" or "ip:port"
    node: []const u8, // "ip:port"
};

pub const Explorer = struct {
    allocator: std.mem.Allocator,
    known_nodes: std.ArrayList(yam.PeerInfo),
    connections: std.AutoHashMap(std.posix.socket_t, *Connection),
    seen_nodes: std.StringHashMap(void), // for deduplication
    edges: std.ArrayList(Edge), // graph relationships

    // Thread communication
    manager_thread: ?std.Thread,
    pending_commands: std.ArrayList(ManagerCommand),
    mutex: std.Thread.Mutex,
    should_stop: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator) !*Explorer {
        const self = try allocator.create(Explorer);
        self.* = .{
            .allocator = allocator,
            .known_nodes = std.ArrayList(yam.PeerInfo).empty,
            .connections = std.AutoHashMap(std.posix.socket_t, *Connection).init(allocator),
            .seen_nodes = std.StringHashMap(void).init(allocator),
            .edges = std.ArrayList(Edge).empty,
            .manager_thread = null,
            .pending_commands = std.ArrayList(ManagerCommand).empty,
            .mutex = .{},
            .should_stop = std.atomic.Value(bool).init(false),
        };
        return self;
    }

    pub fn deinit(self: *Explorer) void {
        // Signal stop and wait for manager thread
        self.should_stop.store(true, .release);
        if (self.manager_thread) |thread| {
            thread.join();
        }

        // Close all connections
        var conn_iter = self.connections.valueIterator();
        while (conn_iter.next()) |conn_ptr| {
            const conn = conn_ptr.*;
            std.posix.close(conn.socket);
            self.allocator.destroy(conn);
        }
        self.connections.deinit();

        // Free seen_nodes keys
        var seen_iter = self.seen_nodes.keyIterator();
        while (seen_iter.next()) |key| {
            self.allocator.free(key.*);
        }
        self.seen_nodes.deinit();

        // Free edges
        for (self.edges.items) |edge| {
            self.allocator.free(edge.source);
            self.allocator.free(edge.node);
        }
        self.edges.deinit(self.allocator);

        self.known_nodes.deinit(self.allocator);
        self.pending_commands.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn run(self: *Explorer) !void {
        // Setup stdout per AGENT.md pattern
        var stdout_buffer: [4096]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
        const stdout = &stdout_writer.interface;

        try stdout.print("Yam Explorer - type 'help' for commands\n\n", .{});
        try stdout.flush();

        // Start manager thread
        self.manager_thread = try std.Thread.spawn(.{}, managerThread, .{self});

        // REPL loop - read line by line from stdin
        while (!self.should_stop.load(.acquire)) {
            try stdout.print("> ", .{});
            try stdout.flush();

            // Read line byte-by-byte (simple and reliable)
            var line_buf: [256]u8 = undefined;
            var line_len: usize = 0;

            while (line_len < line_buf.len) {
                var byte_buf: [1]u8 = undefined;
                const n = std.fs.File.stdin().read(&byte_buf) catch break;
                if (n == 0) break; // EOF
                if (byte_buf[0] == '\n') break;
                line_buf[line_len] = byte_buf[0];
                line_len += 1;
            }

            // EOF check
            if (line_len == 0) {
                // Check if we actually got EOF vs empty line
                var check_buf: [1]u8 = undefined;
                const check = std.fs.File.stdin().read(&check_buf) catch break;
                if (check == 0) break; // Real EOF
                // Was just empty line, continue
                continue;
            }

            const line = line_buf[0..line_len];

            self.handleCommand(line, stdout) catch |err| {
                try stdout.print("Error: {}\n", .{err});
            };
            try stdout.flush();
        }
    }

    fn handleCommand(self: *Explorer, line: []const u8, stdout: anytype) !void {
        var iter = std.mem.tokenizeScalar(u8, line, ' ');
        const cmd = iter.next() orelse return;

        if (std.mem.eql(u8, cmd, "discover")) {
            try self.cmdDiscover(stdout);
        } else if (std.mem.eql(u8, cmd, "nodes")) {
            try self.cmdNodes(stdout);
        } else if (std.mem.eql(u8, cmd, "connect")) {
            try self.cmdConnect(&iter, stdout);
        } else if (std.mem.eql(u8, cmd, "connections")) {
            try self.cmdConnections(stdout);
        } else if (std.mem.eql(u8, cmd, "disconnect")) {
            try self.cmdDisconnect(&iter, stdout);
        } else if (std.mem.eql(u8, cmd, "stream")) {
            try self.cmdStream(&iter, stdout);
        } else if (std.mem.eql(u8, cmd, "getaddr")) {
            try self.cmdGetaddr(&iter, stdout);
        } else if (std.mem.eql(u8, cmd, "graph")) {
            try self.cmdGraph(stdout);
        } else if (std.mem.eql(u8, cmd, "help")) {
            try self.cmdHelp(stdout);
        } else if (std.mem.eql(u8, cmd, "quit") or std.mem.eql(u8, cmd, "exit")) {
            self.should_stop.store(true, .release);
        } else {
            try stdout.print("Unknown command: {s}\n", .{cmd});
        }
    }

    fn cmdDiscover(self: *Explorer, stdout: anytype) !void {
        try stdout.print("Discovering nodes via DNS...\n", .{});

        var node_list = try scout.discoverPeers(self.allocator);
        defer node_list.deinit(self.allocator);

        var added: usize = 0;
        for (node_list.items) |node| {
            const key = try self.formatNodeKey(node);

            // Always add edge (dns -> node)
            try self.edges.append(self.allocator, .{
                .source = try self.allocator.dupe(u8, "dns"),
                .node = try self.allocator.dupe(u8, key),
            });

            // Only add to known_nodes if new
            if (!self.seen_nodes.contains(key)) {
                try self.seen_nodes.put(key, {});
                try self.known_nodes.append(self.allocator, node);
                added += 1;
            } else {
                self.allocator.free(key);
            }
        }

        try stdout.print("Found {d} nodes ({d} new)\n", .{ node_list.items.len, added });
    }

    fn cmdNodes(self: *Explorer, stdout: anytype) !void {
        if (self.known_nodes.items.len == 0) {
            try stdout.print("No nodes known. Run 'discover' first.\n", .{});
            return;
        }

        try stdout.print("Known nodes ({d}):\n", .{self.known_nodes.items.len});
        for (self.known_nodes.items, 0..) |node, i| {
            const addr_str = node.format();
            try stdout.print("[{d:>3}] {s}\n", .{ i + 1, std.mem.sliceTo(&addr_str, ' ') });
        }
    }

    fn cmdConnect(self: *Explorer, iter: *std.mem.TokenIterator(u8, .scalar), stdout: anytype) !void {
        var count: usize = 0;
        while (iter.next()) |arg| {
            const idx = std.fmt.parseInt(usize, arg, 10) catch {
                try stdout.print("Invalid index: {s}\n", .{arg});
                continue;
            };

            if (idx == 0 or idx > self.known_nodes.items.len) {
                try stdout.print("Index out of range: {d}\n", .{idx});
                continue;
            }

            const node = self.known_nodes.items[idx - 1];
            self.mutex.lock();
            self.pending_commands.append(self.allocator, .{ .connect = node }) catch {};
            self.mutex.unlock();
            count += 1;
        }

        if (count == 0) {
            try stdout.print("Usage: connect <index> [index...]\n", .{});
        } else {
            try stdout.print("Connecting to {d} node(s)...\n", .{count});
        }
    }

    fn cmdConnections(self: *Explorer, stdout: anytype) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.connections.count() == 0) {
            try stdout.print("No active connections.\n", .{});
            return;
        }

        try stdout.print("Active connections ({d}):\n", .{self.connections.count()});
        var conn_iter = self.connections.valueIterator();
        var i: usize = 1;
        while (conn_iter.next()) |conn_ptr| {
            const conn = conn_ptr.*;
            const addr_str = conn.peer.format();
            const state_str = switch (conn.state) {
                .connecting => "connecting",
                .handshaking => "handshaking",
                .connected => if (conn.streaming) "stream:on" else "stream:off",
            };
            try stdout.print("[{d}] {s} {s}\n", .{ i, std.mem.sliceTo(&addr_str, ' '), state_str });
            i += 1;
        }
    }

    fn cmdDisconnect(self: *Explorer, iter: *std.mem.TokenIterator(u8, .scalar), stdout: anytype) !void {
        const arg = iter.next() orelse {
            try stdout.print("Usage: disconnect <index>\n", .{});
            return;
        };

        const idx = std.fmt.parseInt(usize, arg, 10) catch {
            try stdout.print("Invalid index: {s}\n", .{arg});
            return;
        };

        self.mutex.lock();
        defer self.mutex.unlock();

        var conn_iter = self.connections.valueIterator();
        var i: usize = 1;
        while (conn_iter.next()) |conn_ptr| {
            if (i == idx) {
                const conn = conn_ptr.*;
                try self.pending_commands.append(self.allocator, .{ .disconnect = conn.socket });
                try stdout.print("Disconnecting...\n", .{});
                return;
            }
            i += 1;
        }

        try stdout.print("Connection not found: {d}\n", .{idx});
    }

    fn cmdStream(self: *Explorer, iter: *std.mem.TokenIterator(u8, .scalar), stdout: anytype) !void {
        const idx_str = iter.next() orelse {
            try stdout.print("Usage: stream <index> on|off\n", .{});
            return;
        };
        const on_off = iter.next() orelse {
            try stdout.print("Usage: stream <index> on|off\n", .{});
            return;
        };

        const idx = std.fmt.parseInt(usize, idx_str, 10) catch {
            try stdout.print("Invalid index: {s}\n", .{idx_str});
            return;
        };

        const enabled = std.mem.eql(u8, on_off, "on");

        self.mutex.lock();
        defer self.mutex.unlock();

        var conn_iter = self.connections.valueIterator();
        var i: usize = 1;
        while (conn_iter.next()) |conn_ptr| {
            if (i == idx) {
                const conn = conn_ptr.*;
                try self.pending_commands.append(self.allocator, .{
                    .set_streaming = .{ .socket = conn.socket, .enabled = enabled },
                });
                try stdout.print("Streaming {s}\n", .{if (enabled) "enabled" else "disabled"});
                return;
            }
            i += 1;
        }

        try stdout.print("Connection not found: {d}\n", .{idx});
    }

    fn cmdGetaddr(self: *Explorer, iter: *std.mem.TokenIterator(u8, .scalar), stdout: anytype) !void {
        const arg = iter.next() orelse {
            try stdout.print("Usage: getaddr <index>\n", .{});
            return;
        };

        const idx = std.fmt.parseInt(usize, arg, 10) catch {
            try stdout.print("Invalid index: {s}\n", .{arg});
            return;
        };

        self.mutex.lock();
        defer self.mutex.unlock();

        var conn_iter = self.connections.valueIterator();
        var i: usize = 1;
        while (conn_iter.next()) |conn_ptr| {
            if (i == idx) {
                const conn = conn_ptr.*;
                if (conn.state != .connected) {
                    try stdout.print("Connection not ready\n", .{});
                    return;
                }
                try self.pending_commands.append(self.allocator, .{ .send_getaddr = conn.socket });
                try stdout.print("Sent getaddr\n", .{});
                return;
            }
            i += 1;
        }

        try stdout.print("Connection not found: {d}\n", .{idx});
    }

    fn cmdGraph(self: *Explorer, stdout: anytype) !void {
        if (self.edges.items.len == 0) {
            try stdout.print("No edges in graph. Run 'discover' first.\n", .{});
            return;
        }

        try stdout.print("Network graph ({d} edges):\n", .{self.edges.items.len});
        for (self.edges.items) |edge| {
            try stdout.print("  {s} <- {s}\n", .{ edge.node, edge.source });
        }
    }

    fn cmdHelp(self: *Explorer, stdout: anytype) !void {
        _ = self;
        try stdout.print(
            \\Commands:
            \\  discover          - Discover nodes via DNS seeds
            \\  nodes             - List known nodes
            \\  connect <n...>    - Connect to node(s) by index
            \\  connections       - List active connections (peers)
            \\  disconnect <n>    - Disconnect from peer
            \\  stream <n> on|off - Toggle message streaming
            \\  getaddr <n>       - Request addresses from peer
            \\  graph             - Show network graph
            \\  help              - Show this help
            \\  quit              - Exit
            \\
        , .{});
    }

    fn formatNodeKey(self: *Explorer, node: yam.PeerInfo) ![]u8 {
        const addr_str = node.format();
        return try self.allocator.dupe(u8, std.mem.sliceTo(&addr_str, ' '));
    }

    // =========================================================================
    // Manager Thread - handles all I/O via poll()
    // =========================================================================

    fn managerThread(self: *Explorer) void {
        while (!self.should_stop.load(.acquire)) {
            self.processPendingCommands();
            self.pollConnections();
        }
    }

    fn processPendingCommands(self: *Explorer) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        while (self.pending_commands.items.len > 0) {
            const cmd = self.pending_commands.orderedRemove(0);
            switch (cmd) {
                .connect => |peer| self.startConnect(peer),
                .disconnect => |socket| self.closeConnection(socket),
                .set_streaming => |s| self.setStreaming(s.socket, s.enabled),
                .send_getaddr => |socket| self.sendGetaddr(socket),
            }
        }
    }

    fn startConnect(self: *Explorer, peer: yam.PeerInfo) void {
        // Create non-blocking socket
        const socket = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK, 0) catch return;
        errdefer std.posix.close(socket);

        // Start non-blocking connect
        std.posix.connect(socket, &peer.address.any, @sizeOf(std.posix.sockaddr.in)) catch |err| {
            if (err != error.WouldBlock) {
                std.posix.close(socket);
                return;
            }
            // WouldBlock is expected for non-blocking connect
        };

        // Create connection record
        const conn = self.allocator.create(Connection) catch {
            std.posix.close(socket);
            return;
        };
        conn.* = .{
            .socket = socket,
            .peer = peer,
            .state = .connecting,
            .streaming = false,
            .handshake_state = .{},
        };

        self.connections.put(socket, conn) catch {
            self.allocator.destroy(conn);
            std.posix.close(socket);
        };
    }

    fn closeConnection(self: *Explorer, socket: std.posix.socket_t) void {
        if (self.connections.fetchRemove(socket)) |entry| {
            std.posix.close(socket);
            self.allocator.destroy(entry.value);
        }
    }

    fn setStreaming(self: *Explorer, socket: std.posix.socket_t, enabled: bool) void {
        if (self.connections.get(socket)) |conn| {
            conn.streaming = enabled;
        }
    }

    fn sendGetaddr(_: *Explorer, socket: std.posix.socket_t) void {
        const checksum = yam.calculateChecksum(&.{});
        const header = yam.MessageHeader.new("getaddr", 0, checksum);
        _ = std.posix.write(socket, std.mem.asBytes(&header)) catch {};
    }

    fn pollConnections(self: *Explorer) void {
        self.mutex.lock();
        const count = self.connections.count();
        self.mutex.unlock();

        if (count == 0) {
            std.Thread.sleep(100_000_000); // 100ms
            return;
        }

        var fds: [MAX_CONNECTIONS]std.posix.pollfd = undefined;
        var sockets: [MAX_CONNECTIONS]std.posix.socket_t = undefined;
        var fd_count: usize = 0;

        self.mutex.lock();
        var conn_iter = self.connections.iterator();
        while (conn_iter.next()) |entry| {
            if (fd_count >= MAX_CONNECTIONS) break;
            const conn = entry.value_ptr.*;
            sockets[fd_count] = conn.socket;
            fds[fd_count] = .{
                .fd = conn.socket,
                .events = if (conn.state == .connecting) std.posix.POLL.OUT else std.posix.POLL.IN,
                .revents = 0,
            };
            fd_count += 1;
        }
        self.mutex.unlock();

        if (fd_count == 0) return;

        const ready = std.posix.poll(fds[0..fd_count], 100) catch return;
        if (ready == 0) return;

        for (fds[0..fd_count], sockets[0..fd_count]) |fd, socket| {
            if (fd.revents == 0) continue;

            if (fd.revents & std.posix.POLL.OUT != 0) {
                self.handleConnectComplete(socket);
            }
            if (fd.revents & std.posix.POLL.IN != 0) {
                self.handleIncoming(socket);
            }
            if (fd.revents & (std.posix.POLL.ERR | std.posix.POLL.HUP) != 0) {
                self.mutex.lock();
                self.closeConnection(socket);
                self.mutex.unlock();
            }
        }
    }

    fn handleConnectComplete(self: *Explorer, socket: std.posix.socket_t) void {
        self.mutex.lock();
        const conn = self.connections.get(socket) orelse {
            self.mutex.unlock();
            return;
        };
        conn.state = .handshaking;
        self.mutex.unlock();

        // Check if connect actually succeeded
        var err_buf: [@sizeOf(c_int)]u8 = undefined;
        std.posix.getsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.ERROR, &err_buf) catch {
            self.mutex.lock();
            self.closeConnection(socket);
            self.mutex.unlock();
            return;
        };
        const err = std.mem.bytesToValue(c_int, &err_buf);

        if (err != 0) {
            self.mutex.lock();
            self.closeConnection(socket);
            self.mutex.unlock();
            return;
        }

        // Send version message
        self.sendVersionMessage(socket) catch {
            self.mutex.lock();
            self.closeConnection(socket);
            self.mutex.unlock();
        };
    }

    fn sendVersionMessage(self: *Explorer, socket: std.posix.socket_t) !void {
        _ = self;
        var nonce: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&nonce));

        const version_payload = yam.VersionPayload{
            .timestamp = std.time.timestamp(),
            .nonce = nonce,
            .relay = true,
        };

        var payload_buffer: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&payload_buffer);
        try version_payload.serialize(fbs.writer());
        const payload = fbs.getWritten();

        const checksum = yam.calculateChecksum(payload);
        const header = yam.MessageHeader.new("version", @intCast(payload.len), checksum);

        _ = try std.posix.write(socket, std.mem.asBytes(&header));
        _ = try std.posix.write(socket, payload);
    }

    fn handleIncoming(self: *Explorer, socket: std.posix.socket_t) void {
        var header_buf: [24]u8 align(4) = undefined;
        const header_read = std.posix.read(socket, &header_buf) catch {
            self.mutex.lock();
            self.closeConnection(socket);
            self.mutex.unlock();
            return;
        };

        if (header_read == 0) {
            self.mutex.lock();
            self.closeConnection(socket);
            self.mutex.unlock();
            return;
        }

        if (header_read < 24) return; // Partial read, wait for more

        const header = std.mem.bytesAsValue(yam.MessageHeader, &header_buf).*;
        if (header.magic != 0xD9B4BEF9) return;

        // Read payload
        var payload: [65536]u8 = undefined;
        const payload_len = @min(header.length, payload.len);
        var payload_read: usize = 0;
        if (payload_len > 0) {
            payload_read = std.posix.read(socket, payload[0..payload_len]) catch 0;
        }

        const cmd = std.mem.sliceTo(&header.command, 0);

        self.mutex.lock();
        const conn = self.connections.get(socket);
        self.mutex.unlock();

        if (conn == null) return;

        // Handle handshake
        if (conn.?.state == .handshaking) {
            self.handleHandshakeMessage(socket, conn.?, cmd, payload[0..payload_read]);
            return;
        }

        // Handle regular messages
        if (std.mem.eql(u8, cmd, "ping")) {
            self.sendPong(socket, payload[0..payload_read]);
        } else if (std.mem.eql(u8, cmd, "addr")) {
            self.handleAddrMessage(conn.?, payload[0..payload_read]);
        }

        // Print if streaming (skip addr since it's always logged in handleAddrMessage)
        if (conn.?.streaming and !std.mem.eql(u8, cmd, "addr")) {
            const addr_str = conn.?.peer.format();
            std.debug.print("[{s}] {s}", .{ std.mem.sliceTo(&addr_str, ' '), cmd });
            if (std.mem.eql(u8, cmd, "inv")) {
                if (payload_read > 0) {
                    std.debug.print(": {d} item(s)", .{payload[0]});
                }
            }
            std.debug.print("\n", .{});
        }
    }

    fn handleHandshakeMessage(_: *Explorer, socket: std.posix.socket_t, conn: *Connection, cmd: []const u8, payload: []const u8) void {
        _ = payload;

        if (std.mem.eql(u8, cmd, "version")) {
            conn.handshake_state.received_version = true;
            if (!conn.handshake_state.sent_verack) {
                conn.handshake_state.sent_verack = true;
                const checksum = yam.calculateChecksum(&.{});
                const header = yam.MessageHeader.new("verack", 0, checksum);
                _ = std.posix.write(socket, std.mem.asBytes(&header)) catch {};
            }
        } else if (std.mem.eql(u8, cmd, "verack")) {
            conn.handshake_state.received_verack = true;
        }

        if (conn.handshake_state.received_version and conn.handshake_state.received_verack) {
            conn.state = .connected;
            const addr_str = conn.peer.format();
            std.debug.print("[{s}] connected\n", .{std.mem.sliceTo(&addr_str, ' ')});
        }
    }

    fn sendPong(self: *Explorer, socket: std.posix.socket_t, ping_payload: []const u8) void {
        _ = self;
        const checksum = yam.calculateChecksum(ping_payload);
        const header = yam.MessageHeader.new("pong", @intCast(ping_payload.len), checksum);
        _ = std.posix.write(socket, std.mem.asBytes(&header)) catch {};
        if (ping_payload.len > 0) {
            _ = std.posix.write(socket, ping_payload) catch {};
        }
    }

    fn handleAddrMessage(self: *Explorer, conn: *Connection, payload: []const u8) void {
        if (payload.len < 1) return;

        var fbs = std.io.fixedBufferStream(payload);
        const addr_msg = yam.AddrMessage.deserialize(fbs.reader(), self.allocator) catch return;
        defer addr_msg.deinit(self.allocator);

        const source_key = self.formatNodeKey(conn.peer) catch return;

        var added: usize = 0;
        var edges_added: usize = 0;
        for (addr_msg.addresses) |net_addr| {
            if (net_addr.toPeerInfo(.addr_message)) |node| {
                const key = self.formatNodeKey(node) catch continue;

                // Always add edge (source -> node)
                self.edges.append(self.allocator, .{
                    .source = self.allocator.dupe(u8, source_key) catch continue,
                    .node = self.allocator.dupe(u8, key) catch continue,
                }) catch continue;
                edges_added += 1;

                // Only add to known_nodes if new
                if (!self.seen_nodes.contains(key)) {
                    self.seen_nodes.put(key, {}) catch {
                        self.allocator.free(key);
                        continue;
                    };
                    self.known_nodes.append(self.allocator, node) catch {};
                    added += 1;
                } else {
                    self.allocator.free(key);
                }
            }
        }

        self.allocator.free(source_key);

        // Always log addr responses (they're typically from explicit getaddr requests)
        const addr_str = conn.peer.format();
        std.debug.print("[{s}] addr: {d} addrs, {d} new nodes, {d} edges\n", .{
            std.mem.sliceTo(&addr_str, ' '),
            addr_msg.addresses.len,
            added,
            edges_added,
        });
    }
};
