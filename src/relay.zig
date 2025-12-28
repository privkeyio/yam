// Relay.zig - Transaction relay and broadcast module
// Named after the relay stations that rapidly transmitted messages across vast distances

const std = @import("std");
const yam = @import("root.zig");
const Courier = @import("courier.zig").Courier;

/// Timing strategy for transaction broadcast
pub const TimingStrategy = enum {
    /// Send to all peers simultaneously (fastest propagation)
    simultaneous,
    /// Stagger sends with random delays (better privacy)
    staggered_random,
};

/// Options for broadcast operation
pub const BroadcastOptions = struct {
    strategy: TimingStrategy = .simultaneous,
    min_delay_ms: u32 = 100,
    max_delay_ms: u32 = 5000,
};

/// Result of a broadcast attempt to a single peer
pub const BroadcastReport = struct {
    peer: yam.PeerInfo,
    success: bool,
    rejected: bool,
    reject_reason: ?[]u8,
    elapsed_ms: u64,

    pub fn deinit(self: *BroadcastReport, allocator: std.mem.Allocator) void {
        if (self.reject_reason) |reason| {
            allocator.free(reason);
        }
    }
};

/// Result of broadcasting to multiple peers
pub const BroadcastResult = struct {
    reports: []BroadcastReport,
    success_count: usize,
    reject_count: usize,

    pub fn deinit(self: *BroadcastResult, allocator: std.mem.Allocator) void {
        for (self.reports) |*report| {
            report.deinit(allocator);
        }
        allocator.free(self.reports);
    }
};

/// Relay manages connections to multiple peers for transaction broadcast
pub const Relay = struct {
    couriers: []Courier,
    allocator: std.mem.Allocator,

    pub fn init(peers: []const yam.PeerInfo, allocator: std.mem.Allocator) !Relay {
        const couriers = try allocator.alloc(Courier, peers.len);
        errdefer allocator.free(couriers);

        for (couriers, peers) |*courier, peer| {
            courier.* = Courier.init(peer, allocator);
        }

        return .{
            .couriers = couriers,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Relay) void {
        for (self.couriers) |*courier| {
            courier.deinit();
        }
        self.allocator.free(self.couriers);
    }

    /// Connect to all peers, performing handshake
    /// Returns the number of successful connections
    pub fn connectAll(self: *Relay) usize {
        var connected: usize = 0;

        for (self.couriers) |*courier| {
            const addr_str = courier.peer.format();
            std.debug.print("Connecting to {s}... ", .{std.mem.sliceTo(&addr_str, ' ')});

            courier.connect() catch |err| {
                std.debug.print("FAILED ({s})\n", .{@errorName(err)});
                continue;
            };

            std.debug.print("OK\n", .{});
            connected += 1;
        }

        return connected;
    }

    /// Broadcast a transaction to all connected peers
    pub fn broadcastTx(self: *Relay, tx_bytes: []const u8, options: BroadcastOptions) !BroadcastResult {
        var reports = try self.allocator.alloc(BroadcastReport, self.couriers.len);
        errdefer self.allocator.free(reports);

        var success_count: usize = 0;
        var reject_count: usize = 0;

        // Initialize RNG for staggered timing
        var rng_seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&rng_seed));
        var rng = std.Random.DefaultPrng.init(rng_seed);

        for (self.couriers, 0..) |*courier, i| {
            // Apply delay for staggered strategy
            if (options.strategy == .staggered_random and i > 0) {
                const delay = rng.random().intRangeAtMost(u32, options.min_delay_ms, options.max_delay_ms);
                std.Thread.sleep(@as(u64, delay) * std.time.ns_per_ms);
            }

            const start = std.time.milliTimestamp();
            var report = BroadcastReport{
                .peer = courier.peer,
                .success = false,
                .rejected = false,
                .reject_reason = null,
                .elapsed_ms = 0,
            };

            if (!courier.connected) {
                report.elapsed_ms = @intCast(std.time.milliTimestamp() - start);
                reports[i] = report;
                continue;
            }

            // Send transaction
            courier.sendTx(tx_bytes) catch |err| {
                std.debug.print("Failed to send tx to peer: {s}\n", .{@errorName(err)});
                report.elapsed_ms = @intCast(std.time.milliTimestamp() - start);
                reports[i] = report;
                continue;
            };

            // Wait briefly for potential reject message
            const reject_result = courier.waitForReject(1000) catch null;

            if (reject_result) |reject| {
                report.rejected = true;
                report.reject_reason = reject;
                reject_count += 1;
            } else {
                report.success = true;
                success_count += 1;
            }

            report.elapsed_ms = @intCast(std.time.milliTimestamp() - start);
            reports[i] = report;
        }

        return .{
            .reports = reports,
            .success_count = success_count,
            .reject_count = reject_count,
        };
    }
};

/// Print a formatted broadcast report
pub fn printBroadcastReport(reports: []const BroadcastReport, allocator: std.mem.Allocator) void {
    _ = allocator;

    std.debug.print("\n=== Broadcast Report ===\n", .{});

    for (reports) |report| {
        const addr_str = report.peer.format();
        const status = if (report.success)
            "SUCCESS"
        else if (report.rejected)
            "REJECTED"
        else
            "FAILED";

        std.debug.print("{s}: {s} ({d}ms)\n", .{
            std.mem.sliceTo(&addr_str, ' '),
            status,
            report.elapsed_ms,
        });

        if (report.reject_reason) |reason| {
            std.debug.print("  Reason: {s}\n", .{reason});
        }
    }
}
