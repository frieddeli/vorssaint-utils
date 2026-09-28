// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Vorssaint

import Foundation
import SQLite3

/// Reads OpenCode sessions and messages from its SQLite database (~/.local/share/opencode/opencode.db).
enum AgentOpenCodeReader {
    /// Reads newly created or updated messages since `cursor.offset` (millisecond timestamp).
    /// Calls `line` with a JSON payload for each message.
    static func readAppended(_ cursor: AgentLogCursor, shouldContinue: () -> Bool = { true },
                             line: (Data) -> Void) {
        guard shouldContinue() else { return }
        var info = stat()
        guard stat(cursor.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return }
        let identity = UInt64(info.st_ino)

        // Check if database was replaced or recreated
        if identity != cursor.identity {
            cursor.identity = identity
            cursor.offset = 0
            cursor.state = AgentLogState()
        }

        var walInfo = stat()
        let walPath = cursor.path + "-wal"
        let walModified: Date
        if stat(walPath, &walInfo) == 0 {
            walModified = Date(timeIntervalSince1970: TimeInterval(walInfo.st_mtimespec.tv_sec)
                               + TimeInterval(walInfo.st_mtimespec.tv_nsec) / 1_000_000_000)
        } else {
            walModified = Date.distantPast
        }

        let dbModified = Date(timeIntervalSince1970: TimeInterval(info.st_mtimespec.tv_sec)
                              + TimeInterval(info.st_mtimespec.tv_nsec) / 1_000_000_000)
        cursor.modified = max(dbModified, walModified)

        var db: OpaquePointer?
        guard sqlite3_open_v2(cursor.path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nil) == SQLITE_OK else {
            return
        }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 2000)

        let since = Int64(cursor.offset)
        let query = """
        SELECT m.id, m.session_id, m.time_created, m.time_updated, s.directory, m.data
        FROM message m
        JOIN session s ON m.session_id = s.id
        WHERE m.time_created > ? OR m.time_updated > ?
        ORDER BY max(m.time_created, COALESCE(m.time_updated, m.time_created)) ASC
        """

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else {
            return
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_int64(stmt, 1, since)
        sqlite3_bind_int64(stmt, 2, since)

        var maxTimestamp: Int64 = since
        while shouldContinue() && sqlite3_step(stmt) == SQLITE_ROW {
            let id = String(cString: sqlite3_column_text(stmt, 0))
            let sessionID = String(cString: sqlite3_column_text(stmt, 1))
            let created = sqlite3_column_int64(stmt, 2)
            let updated = sqlite3_column_int64(stmt, 3)
            let directory = String(cString: sqlite3_column_text(stmt, 4))
            let dataStr = String(cString: sqlite3_column_text(stmt, 5))

            maxTimestamp = max(maxTimestamp, max(created, updated))

            guard var json = (try? JSONSerialization.jsonObject(with: Data(dataStr.utf8))) as? [String: Any] else {
                continue
            }
            json["id"] = id
            json["session_id"] = sessionID
            json["directory"] = directory
            json["time_created"] = created
            json["time_updated"] = updated

            if let mergedData = try? JSONSerialization.data(withJSONObject: json) {
                line(mergedData)
            }
        }

        cursor.offset = UInt64(maxTimestamp)
    }
}
