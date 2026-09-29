// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Vorssaint

import Foundation
import SQLite3

/// Reads OpenCode sessions and messages from its SQLite database (~/.local/share/opencode/opencode.db).
enum AgentOpenCodeReader {
    /// The one database OpenCode keeps in its data folder.
    static let database = "opencode.db"

    /// Rows are found by when they were saved. One can commit a moment after
    /// a newer row another session saved, so each read looks back this far
    /// and skips the revisions it already handed over.
    static let lookBack: Int64 = 5 * 60 * 1000

    /// When the database or its write-ahead log last changed; nil when there
    /// is no database.
    static func modified(_ path: String) -> Date? {
        var info = stat()
        guard stat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return nil }
        var wal = stat()
        let walModified = stat(path + "-wal", &wal) == 0 ? date(wal.st_mtimespec) : .distantPast
        return max(date(info.st_mtimespec), walModified)
    }

    private static func date(_ time: timespec) -> Date {
        Date(timeIntervalSince1970: TimeInterval(time.tv_sec) + TimeInterval(time.tv_nsec) / 1_000_000_000)
    }

    /// Reads messages saved since `cursor.offset` (millisecond timestamp), or
    /// since `horizon` on a first read. Calls `line` with a JSON payload for
    /// each message.
    static func readAppended(_ cursor: AgentLogCursor, since horizon: Date = .distantPast,
                             shouldContinue: () -> Bool = { true }, line: (Data) -> Void) {
        guard shouldContinue() else { return }
        var info = stat()
        guard stat(cursor.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return }
        let identity = UInt64(info.st_ino)

        // Check if database was replaced or recreated
        if identity != cursor.identity {
            let replaced = cursor.identity != 0
            cursor.identity = identity
            cursor.offset = 0
            cursor.recentRows.removeAll()
            cursor.state = AgentLogState()
            if replaced {
                line(Data(#"{"type":"reset"}"#.utf8))
            }
        }
        cursor.modified = modified(cursor.path) ?? date(info.st_mtimespec)

        var db: OpaquePointer?
        guard sqlite3_open_v2(cursor.path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nil) == SQLITE_OK else {
            return
        }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 2000)

        let hasParentID = exists(db, "SELECT 1 FROM pragma_table_info('session') WHERE name = 'parent_id'")
        let hasParts = exists(db, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'part'")

        // A reply that ends the loop by its finish can still hold tool calls
        // the loop goes on with, and the summary of a compaction OpenCode
        // started on its own is followed by its request to continue. Only
        // each part's type and state are looked at, never its content.
        let toolCalls = hasParts ? """
            CASE WHEN \(field("m.data", "$.role")) = 'assistant'
                AND \(field("m.data", "$.finish")) NOT IN ('tool-calls', 'unknown')
            THEN EXISTS (SELECT 1 FROM part p WHERE p.message_id = m.id
                AND \(field("p.data", "$.type")) = 'tool'
                AND coalesce(\(field("p.data", "$.metadata.providerExecuted")), 0) = 0
                AND NOT (coalesce(\(field("p.data", "$.state.status")), '') = 'error'
                    AND coalesce(\(field("p.data", "$.state.metadata.interrupted")), 0) = 1))
            ELSE 0 END
            """ : "0"
        let autoCompaction = hasParts ? """
            CASE WHEN \(field("m.data", "$.role")) = 'assistant' AND \(field("m.data", "$.summary")) = 1
            THEN EXISTS (SELECT 1 FROM part p WHERE p.message_id = \(field("m.data", "$.parentID"))
                AND \(field("p.data", "$.type")) = 'compaction' AND \(field("p.data", "$.auto")) = 1)
            ELSE 0 END
            """ : "0"

        let floor = Int64(max(0, horizon.timeIntervalSince1970) * 1000)
        let since = cursor.offset == 0 ? floor : max(floor, Int64(cursor.offset) - lookBack)
        let parentCol = hasParentID ? "s.parent_id" : "NULL"
        let query = """
        SELECT m.id, m.session_id, m.time_created, m.time_updated, s.directory, \(parentCol), m.data,
            \(toolCalls), \(autoCompaction)
        FROM message m
        JOIN session s ON m.session_id = s.id
        WHERE max(m.time_created, coalesce(m.time_updated, m.time_created)) >= ?
        ORDER BY m.time_created ASC, m.time_updated ASC
        """

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else {
            return
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_int64(stmt, 1, since)

        var newest = Int64(cursor.offset)

        while shouldContinue() && sqlite3_step(stmt) == SQLITE_ROW {
            // A later version could leave any of these empty; such a row is
            // skipped rather than read as if it held a value.
            guard let id = text(stmt, 0), let sessionID = text(stmt, 1), let dataStr = text(stmt, 6),
                  sqlite3_column_type(stmt, 2) != SQLITE_NULL else { continue }
            let created = sqlite3_column_int64(stmt, 2)
            let updated = sqlite3_column_type(stmt, 3) == SQLITE_NULL ? created : sqlite3_column_int64(stmt, 3)
            let directory = text(stmt, 4) ?? ""
            let parentID = text(stmt, 5) ?? ""

            let stamp = max(created, updated)
            newest = max(newest, stamp)
            // A prompt read once is known; later saves only add its summary.
            // A reply is read again whenever what it holds changes.
            let isUser = dataStr.contains("\"role\":\"user\"") || dataStr.contains("\"role\": \"user\"")
            var hasher = Hasher()
            if !isUser {
                hasher.combine(updated)
                hasher.combine(dataStr)
            }
            let revision = hasher.finalize()
            if let seen = cursor.recentRows[id], isUser || seen.revision == revision { continue }
            cursor.recentRows[id] = (stamp, revision)

            guard var json = (try? JSONSerialization.jsonObject(with: Data(dataStr.utf8))) as? [String: Any] else {
                continue
            }
            json["id"] = id
            json["session_id"] = sessionID
            json["parent_session_id"] = parentID
            json["directory"] = directory
            json["time_created"] = created
            json["time_updated"] = updated
            if sqlite3_column_int64(stmt, 7) != 0 { json["tool_calls"] = true }
            if sqlite3_column_int64(stmt, 8) != 0 { json["auto_compaction"] = true }

            if let mergedData = try? JSONSerialization.data(withJSONObject: json) {
                line(mergedData)
            }
        }

        cursor.offset = UInt64(max(0, newest))
        let kept = newest - lookBack
        cursor.recentRows = cursor.recentRows.filter { $0.value.stamp >= kept }
    }

    private static func text(_ stmt: OpaquePointer?, _ column: Int32) -> String? {
        sqlite3_column_text(stmt, column).map { String(cString: $0) }
    }

    /// A JSON value that reads as null, instead of failing the whole query,
    /// when a row holds something other than JSON.
    private static func field(_ column: String, _ path: String) -> String {
        "(CASE WHEN json_valid(\(column)) THEN json_extract(\(column), '\(path)') END)"
    }

    private static func exists(_ db: OpaquePointer?, _ query: String) -> Bool {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else { return false }
        defer { sqlite3_finalize(stmt) }
        return sqlite3_step(stmt) == SQLITE_ROW
    }
}
