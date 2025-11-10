/**
 * SessionRecord class
 *
 */

import { CLOSED_SESSIONS_MAX, migrations, SESSION_RECORD_VERSION } from "../constants/index.js";
import { BaseKeyType } from "../types/index.js";
import { SessionEntry } from "./session-entry.js";


export class SessionRecord {

  sessions: { [key: string]: SessionEntry };

  version: string;

  static createEntry() {
    return new SessionEntry();
  }

  static migrate(data: any) {
    let run = (data.version === undefined);
    for (let i = 0; i < migrations.length; ++i) {
      if (run) {
        console.info("Migrating session to:", migrations[i].version);
        migrations[i].migrate(data);
      } else if (migrations[i].version === data.version) {
        run = true;
      }
    }
    if (!run) {
      throw new Error("Error migrating SessionRecord");
    }
  }

  static deserialize(data: any) {
    if (data.version !== SESSION_RECORD_VERSION) {
      this.migrate(data);
    }
    const obj: SessionRecord = new this();
    if (data._sessions) {
      for (const [key, entry] of Object.entries(data._sessions)) {
        obj.sessions[key] = SessionEntry.deserialize(entry);
      }
    }
    return obj;
  }

  constructor() {
    this.sessions = {};
    this.version = SESSION_RECORD_VERSION;
  }

  serialize() {
    const _sessions: any = {};
    for (const [key, entry] of Object.entries(this.sessions)) {
      _sessions[key] = entry.serialize();
    }
    return {
      _sessions,
      version: this.version
    };
  }

  haveOpenSession() {
    const openSession: any = this.getOpenSession();
    return (!!openSession && typeof openSession.registrationId === 'number');
  }

  getSession(key: Buffer) {
    const session: any = this.sessions[key.toString('base64')];
    if (session && session.indexInfo.baseKeyType === BaseKeyType.OURS) {
      throw new Error("Tried to lookup a session using our basekey");
    }
    return session;
  }

  getOpenSession() {
    for (const session of Object.values(this.sessions)) {
      if (!this.isClosed(session)) {
        return session;
      }
    }
  }

  setSession(session: any) {
    this.sessions[session.indexInfo.baseKey.toString('base64')] = session;
  }

  getSessions() {
    return Array.from(Object.values(this.sessions)).sort((a, b) => {
      const aUsed = a.indexInfo.used || 0;
      const bUsed = b.indexInfo.used || 0;
      return aUsed === bUsed ? 0 : aUsed < bUsed ? 1 : -1;
    });
  }

  closeSession(session: any) {
    if (this.isClosed(session)) {
      console.warn("Session already closed", session);
      return;
    }
    console.info("Closing session:", session);
    session.indexInfo.closed = Date.now();
  }

  openSession(session: any) {
    if (!this.isClosed(session)) {
      console.warn("Session already open");
    }
    console.info("Opening session:", session);
    session.indexInfo.closed = -1;
  }

  isClosed(session: any) {
    return session.indexInfo.closed !== -1;
  }

  removeOldSessions() {
    while (Object.keys(this.sessions).length > CLOSED_SESSIONS_MAX) {
      let oldestKey;
      let oldestSession;
      for (const [key, session] of Object.entries(this.sessions)) {
        if (session.indexInfo.closed !== -1 &&
          (!oldestSession || session.indexInfo.closed < oldestSession.indexInfo.closed)) {
          oldestKey = key;
          oldestSession = session;
        }
      }
      if (oldestKey) {
        console.info("Removing old closed session:", oldestSession);
        delete this.sessions[oldestKey];
      } else {
        throw new Error('Corrupt sessions object');
      }
    }
  }

  deleteAllSessions() {
    for (const key of Object.keys(this.sessions)) {
      delete this.sessions[key];
    }
  }
}

