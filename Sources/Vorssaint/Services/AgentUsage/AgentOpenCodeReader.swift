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
            let replaced = cursor.identity != 0
            cursor.identity = identity
            cursor.offset = 0
            cursor.boundaryRevisions.removeAll()
            cursor.state = AgentLogState()
            if replaced {
                line(Data(#"{"type":"reset"}"#.utf8))
            }
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

        var hasParentID = false
        var pragmaStmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "PRAGMA table_info(session)", -1, &pragmaStmt, nil) == SQLITE_OK {
            while sqlite3_step(pragmaStmt) == SQLITE_ROW {
                if let name = sqlite3_column_text(pragmaStmt, 1), String(cString: name) == "parent_id" {
                    hasParentID = true
                    break
                }
            }
            sqlite3_finalize(pragmaStmt)
        }

        let since = Int64(cursor.offset)
        let parentCol = hasParentID ? "s.parent_id" : "''"
        let query = """
        SELECT m.id, m.session_id, m.time_created, m.time_updated, s.directory, \(parentCol), m.data
        FROM message m
        JOIN session s ON m.session_id = s.id
        WHERE m.time_created >= ? OR (m.time_updated >= ? AND m.data NOT LIKE '%"role":"user"%')
        ORDER BY m.time_created ASC, m.time_updated ASC
        """

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else {
            return
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_int64(stmt, 1, since)
        sqlite3_bind_int64(stmt, 2, since)

        var maxTimestamp: Int64 = since
        var currentBoundaryRevisions: Set<String> = []

        while shouldContinue() && sqlite3_step(stmt) == SQLITE_ROW {
            let id = String(cString: sqlite3_column_text(stmt, 0))
            let sessionID = String(cString: sqlite3_column_text(stmt, 1))
            let created = sqlite3_column_int64(stmt, 2)
            let updated = sqlite3_column_int64(stmt, 3)
            let directory = String(cString: sqlite3_column_text(stmt, 4))
            let parentID = sqlite3_column_text(stmt, 5).map { String(cString: $0) } ?? ""
            let dataStr = String(cString: sqlite3_column_text(stmt, 6))

            let isUser = dataStr.contains("\"role\":\"user\"") || dataStr.contains("\"role\": \"user\"")
            let rowTimestamp = isUser ? created : max(created, updated)
            let revKey = isUser ? "\(id):\(created)" : "\(id):\(updated):\(dataStr.hashValue)"

            if rowTimestamp < since || (rowTimestamp == since && cursor.boundaryRevisions.contains(revKey)) {
                continue
            }

            if rowTimestamp > maxTimestamp {
                maxTimestamp = rowTimestamp
                currentBoundaryRevisions = [revKey]
            } else if rowTimestamp == maxTimestamp {
                currentBoundaryRevisions.insert(revKey)
            }

            guard var json = (try? JSONSerialization.jsonObject(with: Data(dataStr.utf8))) as? [String: Any] else {
                continue
            }
            json["id"] = id
            json["session_id"] = sessionID
            json["parent_session_id"] = parentID
            json["directory"] = directory
            json["time_created"] = created
            json["time_updated"] = updated

            if let mergedData = try? JSONSerialization.data(withJSONObject: json) {
                line(mergedData)
            }
        }

        if maxTimestamp > since {
            cursor.offset = UInt64(maxTimestamp)
            cursor.boundaryRevisions = currentBoundaryRevisions
        } else if maxTimestamp == since {
            cursor.boundaryRevisions.formUnion(currentBoundaryRevisions)
        }
    }
}
