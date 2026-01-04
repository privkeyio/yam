const std = @import("std");
const yam = @import("root.zig");
const scout = @import("scout.zig");
const Courier = @import("courier.zig").Courier;
const relay = @import("relay.zig");
const Relay = relay.Relay;
const Explorer = @import("explorer.zig").Explorer;

const CliArgs = struct {
    tx_hex: ?[]const u8 = null,
    peer_count: u32 = 5,
    timing: relay.TimingStrategy = .simultaneous,
    min_delay_ms: u32 = 100,
    max_delay_ms: u32 = 5000,
    interactive_select: bool = false,
    discover: bool = false,
    listen_mode: bool = false,
    show_help: bool = false,
};

pub fn main() !void {
    // Setup allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const result = gpa.deinit();
        if (result == .leak) {
            std.debug.print("Memory leak detected\n", .{});
        }
    }
    const allocator = gpa.allocator();

    // Parse command line arguments
    const args = try parseArgs(allocator);

    if (args.show_help) {
        printUsage();
        return;
    }

    if (args.listen_mode) {
        try runListenMode(allocator);
    } else if (args.tx_hex != null) {
        try broadcastTransaction(allocator, args);
    } else {
        // Default: Interactive explore mode
        var explorer = try Explorer.init(allocator);
        defer explorer.deinit();
        try explorer.run();
    }
}

fn parseArgs(allocator: std.mem.Allocator) !CliArgs {
    var args_iter = try std.process.argsWithAllocator(allocator);
    defer args_iter.deinit();

    var result = CliArgs{};

    // Skip program name
    _ = args_iter.next();

    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--tx") or std.mem.eql(u8, arg, "-t")) {
            result.tx_hex = args_iter.next();
        } else if (std.mem.eql(u8, arg, "--peers") or std.mem.eql(u8, arg, "-p")) {
            if (args_iter.next()) |count_str| {
                result.peer_count = std.fmt.parseInt(u32, count_str, 10) catch 5;
            }
        } else if (std.mem.eql(u8, arg, "--staggered") or std.mem.eql(u8, arg, "-s")) {
            result.timing = .staggered_random;
        } else if (std.mem.eql(u8, arg, "--select-peers")) {
            result.interactive_select = true;
        } else if (std.mem.eql(u8, arg, "--discover") or std.mem.eql(u8, arg, "-d")) {
            result.discover = true;
        } else if (std.mem.eql(u8, arg, "--listen") or std.mem.eql(u8, arg, "-l")) {
            result.listen_mode = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            result.show_help = true;
        }
    }

    return result;
}

fn printUsage() void {
    const usage =
        \\Yam - Bitcoin P2P Transaction Courier
        \\
        \\USAGE:
        \\  yam --tx <hex>              Broadcast raw transaction
        \\  yam --listen                Listen for mempool transactions
        \\
        \\BROADCAST OPTIONS:
        \\  --tx, -t <hex>              Raw transaction hex to broadcast
        \\  --peers, -p <count>         Number of peers to broadcast to (default: 5)
        \\  --staggered, -s             Use random delays between broadcasts (privacy)
        \\  --select-peers              Interactive peer selection mode
        \\  --discover, -d              Enable recursive peer discovery via getaddr
        \\
        \\OTHER OPTIONS:
        \\  --listen, -l                Listen for mempool transactions (original mode)
        \\  --help, -h                  Show this help message
        \\
        \\EXAMPLES:
        \\  yam --tx 0100000001... --peers 8 --staggered
        \\  yam --tx 0100000001... --select-peers
        \\  yam --listen
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn broadcastTransaction(allocator: std.mem.Allocator, args: CliArgs) !void {
    const tx_hex = args.tx_hex orelse return error.NoTransactionProvided;

    // Parse transaction hex to validate it
    std.debug.print("=== Validating Transaction ===\n", .{});
    const tx_bytes = yam.hexToBytes(allocator, tx_hex) catch |err| {
        std.debug.print("Error: Invalid transaction hex - {}\n", .{err});
        return err;
    };
    defer allocator.free(tx_bytes);

    // Parse to verify structure and get txid
    var fbs = std.io.fixedBufferStream(tx_bytes);
    const tx = yam.Transaction.deserialize(fbs.reader(), allocator) catch |err| {
        std.debug.print("Error: Failed to parse transaction - {}\n", .{err});
        return err;
    };
    defer tx.deinit(allocator);

    const txid_hex = try tx.txidHex(allocator);
    std.debug.print("Transaction ID: {s}\n", .{txid_hex});
    std.debug.print("Inputs: {d}, Outputs: {d}\n", .{ tx.inputs.len, tx.outputs.len });

    var total_output_value: f64 = 0;
    for (tx.outputs) |output| {
        total_output_value += output.valueBtc();
    }
    std.debug.print("Total output: {d:.8} BTC\n", .{total_output_value});

    // Discover peers
    std.debug.print("\n=== Scouting for Peers ===\n", .{});
    var peer_list = try scout.discoverPeers(allocator);

    if (peer_list.items.len == 0) {
        std.debug.print("Error: No peers discovered\n", .{});
        return error.NoPeersDiscovered;
    }

    // If --discover flag, connect to some peers and request more via getaddr
    if (args.discover) {
        std.debug.print("\n=== Recursive Discovery via getaddr ===\n", .{});
        const expanded_list = try scout.discoverPeersViaGetaddr(allocator, peer_list.items, 3);
        peer_list.deinit(allocator); // Free the initial list after copying
        peer_list = expanded_list;
    }
    defer peer_list.deinit(allocator);

    // Select peers
    var selected_peers: []yam.PeerInfo = undefined;
    if (args.interactive_select) {
        selected_peers = try interactivePeerSelect(allocator, peer_list.items);
    } else {
        selected_peers = try scout.selectRandomPeers(allocator, peer_list.items, args.peer_count);
    }
    defer allocator.free(selected_peers);

    std.debug.print("\nSelected {d} peers for broadcast\n", .{selected_peers.len});

    // Initialize relay
    var r = try Relay.init(selected_peers, allocator);
    defer r.deinit();

    // Connect to all peers
    std.debug.print("\n=== Connecting to Peers ===\n", .{});
    const connected = r.connectAll();
    std.debug.print("\nSuccessfully connected to {d}/{d} peers\n", .{ connected, selected_peers.len });

    if (connected == 0) {
        std.debug.print("Error: No peers connected, aborting broadcast\n", .{});
        return error.NoPeersConnected;
    }

    // Confirm broadcast
    std.debug.print("\n=== Ready to Broadcast ===\n", .{});
    std.debug.print("Transaction: {s}\n", .{txid_hex});
    std.debug.print("Peers: {d}\n", .{connected});
    std.debug.print("Timing: {s}\n", .{if (args.timing == .staggered_random) "staggered (privacy mode)" else "simultaneous"});

    // Broadcast transaction
    std.debug.print("\n=== Dispatching Transaction ===\n", .{});
    var result = try r.broadcastTx(tx_bytes, .{
        .strategy = args.timing,
        .min_delay_ms = args.min_delay_ms,
        .max_delay_ms = args.max_delay_ms,
    });
    defer result.deinit(allocator);

    // Print results
    relay.printBroadcastReport(result.reports, allocator);

    if (result.success_count > 0) {
        std.debug.print("\nTransaction broadcast to {d} peer(s)\n", .{result.success_count});
        if (result.reject_count > 0) {
            std.debug.print("Warning: {d} peer(s) rejected the transaction\n", .{result.reject_count});
        }
    } else {
        std.debug.print("\nError: Broadcast failed to all peers\n", .{});
    }
}

fn interactivePeerSelect(allocator: std.mem.Allocator, peers: []const yam.PeerInfo) ![]yam.PeerInfo {
    std.debug.print("\n=== Available Peers ===\n", .{});
    std.debug.print("Enter peer numbers separated by commas (e.g., 1,3,5,7)\n", .{});
    std.debug.print("Or press Enter for all peers\n\n", .{});

    for (peers, 0..) |peer, i| {
        const addr_str = peer.format();
        const source_str = scout.sourceName(peer.source);
        std.debug.print("  [{d:>3}] {s} {s}\n", .{ i + 1, std.mem.sliceTo(&addr_str, ' '), source_str });
    }

    std.debug.print("\nSelection: ", .{});

    // Read user input from stdin using new Zig 0.15 I/O
    var stdin_buf: [256]u8 = undefined;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buf);
    const reader = &stdin_reader.interface;

    // Read line into buffer using fixed writer
    var line_buf: [256]u8 = undefined;
    var fixed_writer = std.Io.Writer.fixed(&line_buf);
    const bytes_read = reader.streamDelimiter(&fixed_writer, '\n') catch |err| {
        if (err != error.EndOfStream) return error.InputError;
        return try allocator.dupe(yam.PeerInfo, peers); // Return all on EOF
    };
    const line = line_buf[0..bytes_read];

    if (line.len == 0) {
        // Return all peers
        return try allocator.dupe(yam.PeerInfo, peers);
    }

    // Parse comma-separated indices
    var selected = std.ArrayList(yam.PeerInfo).empty;
    errdefer selected.deinit(allocator);

    var iter = std.mem.splitScalar(u8, line, ',');
    while (iter.next()) |num_str| {
        const trimmed = std.mem.trim(u8, num_str, " \t");
        if (trimmed.len == 0) continue;

        const idx = std.fmt.parseInt(usize, trimmed, 10) catch continue;
        if (idx > 0 and idx <= peers.len) {
            try selected.append(allocator, peers[idx - 1]);
        }
    }

    if (selected.items.len == 0) {
        return error.NoPeersSelected;
    }

    return try selected.toOwnedSlice(allocator);
}

// ============================================================================
// Original mempool listening mode (preserved from original implementation)
// ============================================================================

fn runListenMode(allocator: std.mem.Allocator) !void {
    // Setup stdout with buffer
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    const ip = "172.7.56.107";
    const peer_addr = try std.net.Address.parseIp4(ip, 8333);

    std.debug.print("Connecting to peer: {s}\n", .{ip});

    var stream = try std.net.tcpConnectToAddress(peer_addr);
    defer stream.close();

    std.debug.print("Starting handshake\n", .{});

    try performHandshake(stream, allocator);

    std.debug.print("=== Listening for mempool transactions ===\n", .{});
    std.debug.print("Note: Some nodes may close connections to lightweight clients.\n\n", .{});

    listenForMempool(stdout, stream, allocator) catch |err| {
        std.debug.print("\nConnection ended: {}\n", .{err});
        std.debug.print("This is normal - many Bitcoin nodes close lightweight client connections.\n", .{});
    };
}

fn listenForMempool(writer: anytype, stream: std.net.Stream, allocator: std.mem.Allocator) !void {
    var message_count: usize = 0;

    while (true) {
        const message = readMessage(stream, allocator) catch |err| {
            if (err == error.ConnectionClosed) {
                try writer.print("\nConnection closed by peer (received {d} messages)\n", .{message_count});
                return err;
            }
            return err;
        };
        defer if (message.payload.len > 0) allocator.free(message.payload);

        message_count += 1;
        const cmd = std.mem.sliceTo(&message.header.command, 0);

        if (std.mem.eql(u8, cmd, "inv")) {
            const inv_msg = try parseInvMessage(message.payload, allocator);
            try sendMessage(stream, "getdata", message.payload);
            defer inv_msg.deinit(allocator);
        } else if (std.mem.eql(u8, cmd, "ping")) {
            // pong is not needed for mempool listening
        } else if (std.mem.eql(u8, cmd, "sendcmpct")) {
            try writer.print("<<< Received sendcmpct (compact blocks support)\n", .{});
        } else if (std.mem.eql(u8, cmd, "feefilter")) {
            try writer.print("<<< Received feefilter (minimum fee: {d} sat/kB)\n", .{message.payload.len});
        } else if (std.mem.eql(u8, cmd, "addr")) {
            try writer.print("<<< Received addr (peer addresses)\n", .{});
        } else if (std.mem.eql(u8, cmd, "tx")) {
            try handleTxMessage(writer, message.payload, allocator);
        } else if (std.mem.eql(u8, cmd, "reject")) {
            try writer.print("<<< Received reject message\n", .{});
        } else {
            std.debug.print("<<< Received: {s} (len: {d})\n", .{ cmd, message.header.length });
        }
    }
}

fn parseInvMessage(payload: []const u8, allocator: std.mem.Allocator) !yam.InvMessage {
    var fbs = std.io.fixedBufferStream(payload);
    return yam.InvMessage.deserialize(fbs.reader(), allocator);
}

fn handleTxMessage(writer: anytype, payload: []const u8, allocator: std.mem.Allocator) !void {
    var fbs = std.io.fixedBufferStream(payload);
    const tx = try yam.Transaction.deserialize(fbs.reader(), allocator);
    defer tx.deinit(allocator);

    const txid_hex = try tx.txidHex(allocator);

    var total_output_value: f64 = 0;
    for (tx.outputs) |output| {
        total_output_value += output.valueBtc();
    }

    try writer.print("{s} {d}->{d} {d:.8} BTC", .{ txid_hex, tx.inputs.len, tx.outputs.len, total_output_value });

    if (tx.outputs.len >= 3) {
        try writer.print(" [exchange]", .{});
    }

    if (tx.outputs.len == 1 and tx.inputs.len > 2 and tx.inputs.len > tx.outputs.len) {
        try writer.print(" [consolidation]", .{});
    }

    if (total_output_value >= 10.0) {
        try writer.print(" [whale]", .{});
    }
    try writer.print("\n", .{});
}

fn readMessage(stream: std.net.Stream, allocator: std.mem.Allocator) !struct { header: yam.MessageHeader, payload: []u8 } {
    var header_buffer: [24]u8 align(4) = undefined;
    var total_read: usize = 0;
    while (total_read < header_buffer.len) {
        const bytes_read = try stream.read(header_buffer[total_read..]);
        if (bytes_read == 0) {
            return error.ConnectionClosed;
        }
        total_read += bytes_read;
    }

    const header_ptr = std.mem.bytesAsValue(yam.MessageHeader, &header_buffer);
    const header = header_ptr.*;

    if (header.magic != 0xD9B4BEF9) {
        std.debug.print("Invalid magic number: 0x{x}\n", .{header.magic});
        return error.InvalidMagic;
    }

    var payload: []u8 = &.{};
    if (header.length > 0) {
        payload = try allocator.alloc(u8, header.length);
        errdefer allocator.free(payload);

        total_read = 0;
        while (total_read < header.length) {
            const bytes_read = try stream.read(payload[total_read..]);
            if (bytes_read == 0) {
                allocator.free(payload);
                return error.ConnectionClosed;
            }
            total_read += bytes_read;
        }

        const calculated_checksum = yam.calculateChecksum(payload);
        if (calculated_checksum != header.checksum) {
            allocator.free(payload);
            std.debug.print("Checksum mismatch: expected 0x{x}, got 0x{x}\n", .{ header.checksum, calculated_checksum });
            return error.InvalidChecksum;
        }
    }

    return .{ .header = header, .payload = payload };
}

fn sendMessage(stream: std.net.Stream, command: []const u8, payload: []const u8) !void {
    const checksum = yam.calculateChecksum(payload);
    const header = yam.MessageHeader.new(command, @intCast(payload.len), checksum);

    try stream.writeAll(std.mem.asBytes(&header));
    if (payload.len > 0) {
        try stream.writeAll(payload);
    }
}

fn performHandshake(stream: std.net.Stream, allocator: std.mem.Allocator) !void {
    var nonce: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&nonce));

    const version_payload = yam.VersionPayload{
        .timestamp = std.time.timestamp(),
        .nonce = nonce,
        .relay = true,
    };

    var payload_buffer = std.ArrayList(u8).empty;
    defer payload_buffer.deinit(allocator);
    try version_payload.serialize(payload_buffer.writer(allocator));

    std.debug.print(">>> Sending version message...\n", .{});
    try sendMessage(stream, "version", payload_buffer.items);

    var received_version = false;
    var received_verack = false;

    while (!received_version or !received_verack) {
        const message = try readMessage(stream, allocator);
        defer if (message.payload.len > 0) allocator.free(message.payload);

        const cmd = std.mem.sliceTo(&message.header.command, 0);
        std.debug.print("<<< Received: {s} (len: {d})\n", .{ cmd, message.header.length });

        if (std.mem.eql(u8, cmd, "version")) {
            if (received_version) continue;
            received_version = true;

            var fbs = std.io.fixedBufferStream(message.payload);
            const peer_version = try yam.VersionPayload.deserialize(fbs.reader(), allocator);
            defer allocator.free(peer_version.user_agent);

            std.debug.print("Peer version: {d}\n", .{peer_version.version});
            std.debug.print("Peer services: 0x{x}\n", .{peer_version.services});

            const services = yam.ServiceFlags.decode(peer_version.services);
            std.debug.print("  Service flags:\n", .{});
            if (services.network) std.debug.print("    - NODE_NETWORK (full node)\n", .{});
            if (services.bloom) std.debug.print("    - NODE_BLOOM (Bloom filter support)\n", .{});
            if (services.witness) std.debug.print("    - NODE_WITNESS (SegWit support)\n", .{});
            if (services.network_limited) std.debug.print("    - NODE_NETWORK_LIMITED (pruned node)\n", .{});
            if (services.compact_filters) std.debug.print("    - NODE_COMPACT_FILTERS (BIP157/158)\n", .{});

            std.debug.print("Peer user agent: {s}\n", .{peer_version.user_agent});
            std.debug.print("Peer start height: {d}\n", .{peer_version.start_height});

            std.debug.print(">>> Sending verack...\n", .{});
            try sendMessage(stream, "verack", &.{});
        } else if (std.mem.eql(u8, cmd, "verack")) {
            if (received_verack) continue;
            received_verack = true;
            std.debug.print("Handshake complete!\n", .{});
        }
    }
}

test "simple test" {
    const allocator = std.testing.allocator;
    var list = std.ArrayList(i32).empty;
    defer list.deinit(allocator);
    try list.append(allocator, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
