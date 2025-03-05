package com.secure.appNote.services;

import com.secure.appNote.models.AuditLog;
import com.secure.appNote.models.Note;

import java.util.List;

public interface AuditLogService {
    void logNoteCreation(String username, Note note);

    void logNoteUpdate(String username, Note note);

    void logNoteDelete(String username, Long noteId);

    List<AuditLog> getAllAuditLogs();

    List<AuditLog> getAuditLogForNoteId(Long id);
}
