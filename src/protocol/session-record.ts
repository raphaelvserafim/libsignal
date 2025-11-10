/**
 * SessionRecord manages multiple session entries and their lifecycle.
 * @raphaelvserafim
 */

import { CLOSED_SESSIONS_MAX, migrations, SESSION_RECORD_VERSION } from "../constants/index.js";
import { BaseKeyType } from "../types/index.js";
import { SessionEntry } from "./session-entry.js";

/**
 * Limpa dados sensíveis de uma sessão
 */
function secureDestroySession(session: SessionEntry | null | undefined): void {
  if (session && typeof session.destroy === 'function') {
    session.destroy();
  }
}

export class SessionRecord {
  sessions: { [key: string]: SessionEntry };
  version: string;

  static createEntry(): SessionEntry {
    return new SessionEntry();
  }

  static migrate(data: any): void {
    if (!data || typeof data !== 'object') {
      throw new TypeError("Data must be an object for migration");
    }

    let run = (data.version === undefined);
    let migratedToVersion: string | undefined;

    for (let i = 0; i < migrations.length; ++i) {
      if (!migrations[i] || typeof migrations[i].migrate !== 'function') {
        throw new Error(`Invalid migration at index ${i}`);
      }

      if (run) {
        try {
          if (process.env.NODE_ENV !== 'production') {
            console.debug(`Migrating session to: ${migrations[i].version}`);
          }
          migrations[i].migrate(data);
          migratedToVersion = migrations[i].version;
        } catch (error) {
          throw new Error(`Migration to ${migrations[i].version} failed: ${(error as Error).message}`);
        }
      } else if (migrations[i].version === data.version) {
        run = true;
      }
    }

    if (!run) {
      throw new Error(`Error migrating SessionRecord: unknown version ${data.version}`);
    }

    // Validar que a migração foi bem-sucedida
    if (migratedToVersion && data.version !== migratedToVersion) {
      data.version = migratedToVersion;
    }
  }

  static deserialize(data: any): SessionRecord {
    // Validação de entrada
    if (!data || typeof data !== 'object') {
      throw new TypeError("Data must be an object");
    }

    // Verificar e executar migração se necessário
    if (data.version !== SESSION_RECORD_VERSION) {
      this.migrate(data);
    }

    // Validar versão após migração
    if (data.version !== SESSION_RECORD_VERSION) {
      throw new Error(`Invalid version after migration: expected ${SESSION_RECORD_VERSION}, got ${data.version}`);
    }

    const obj: SessionRecord = new this();

    if (data._sessions) {
      if (typeof data._sessions !== 'object') {
        throw new TypeError("_sessions must be an object");
      }

      for (const [key, entryData] of Object.entries(data._sessions)) {
        if (!key || typeof key !== 'string') {
          throw new Error(`Invalid session key: ${key}`);
        }
        if (!entryData || typeof entryData !== 'object') {
          throw new Error(`Invalid session data at key: ${key}`);
        }

        try {
          obj.sessions[key] = SessionEntry.deserialize(entryData);
        } catch (error) {
          throw new Error(`Failed to deserialize session at key ${key}: ${(error as Error).message}`);
        }
      }
    }

    return obj;
  }

  constructor() {
    this.sessions = {};
    this.version = SESSION_RECORD_VERSION;
  }

  serialize(): { _sessions: any, version: string } {
    const _sessions: any = {};

    for (const [key, entry] of Object.entries(this.sessions)) {
      if (!entry || !(entry instanceof SessionEntry)) {
        throw new Error(`Invalid session entry at key: ${key}`);
      }

      try {
        _sessions[key] = entry.serialize();
      } catch (error) {
        throw new Error(`Failed to serialize session at key ${key}: ${(error as Error).message}`);
      }
    }

    return {
      _sessions,
      version: this.version
    };
  }

  haveOpenSession(): boolean {
    const openSession = this.getOpenSession();
    return (!!openSession && typeof openSession.registrationId === 'number');
  }

  getSession(key: Buffer): SessionEntry | undefined {
    // Validação de entrada
    if (!key) {
      throw new TypeError("key is required");
    }
    if (!Buffer.isBuffer(key)) {
      throw new TypeError("key must be a Buffer");
    }

    const sessionKey = key.toString('base64');
    const session = this.sessions[sessionKey];

    if (!session) {
      return undefined;
    }

    // Validação de integridade
    if (!session.indexInfo || session.indexInfo.baseKeyType === undefined) {
      throw new Error("Session has invalid indexInfo");
    }

    if (session.indexInfo.baseKeyType === BaseKeyType.OURS) {
      throw new Error("Tried to lookup a session using our basekey");
    }

    return session;
  }

  getOpenSession(): SessionEntry | undefined {
    for (const session of Object.values(this.sessions)) {
      if (!session || !(session instanceof SessionEntry)) {
        continue;
      }
      if (!this.isClosed(session)) {
        return session;
      }
    }
    return undefined;
  }

  setSession(session: SessionEntry): void {
    // Validação de entrada
    if (!session || !(session instanceof SessionEntry)) {
      throw new TypeError("session must be a SessionEntry instance");
    }
    if (!session.indexInfo || !session.indexInfo.baseKey) {
      throw new Error("Session must have valid indexInfo with baseKey");
    }
    if (!Buffer.isBuffer(session.indexInfo.baseKey)) {
      throw new TypeError("session.indexInfo.baseKey must be a Buffer");
    }

    const key = session.indexInfo.baseKey.toString('base64');

    // Se já existe uma sessão com essa chave, limpar a antiga
    if (this.sessions[key]) {
      secureDestroySession(this.sessions[key]);
    }

    this.sessions[key] = session;
  }

  getSessions(): SessionEntry[] {
    const sessions = Array.from(Object.values(this.sessions))
      .filter(session => session instanceof SessionEntry);

    return sessions.sort((a, b) => {
      const aUsed = a.indexInfo?.used || 0;
      const bUsed = b.indexInfo?.used || 0;
      return aUsed === bUsed ? 0 : aUsed < bUsed ? 1 : -1;
    });
  }

  closeSession(session: SessionEntry): void {
    // Validação de entrada
    if (!session || !(session instanceof SessionEntry)) {
      throw new TypeError("session must be a SessionEntry instance");
    }
    if (!session.indexInfo) {
      throw new Error("Session must have valid indexInfo");
    }

    if (this.isClosed(session)) {
      if (process.env.NODE_ENV !== 'production') {
        console.warn("Attempted to close already closed session");
      }
      return;
    }

    if (process.env.NODE_ENV !== 'production') {
      const baseKeyPreview = session.indexInfo.baseKey
        ? session.indexInfo.baseKey.toString('base64').substring(0, 8) + '...'
        : 'unknown';
      console.debug(`Closing session with baseKey: ${baseKeyPreview}`);
    }

    session.indexInfo.closed = Date.now();
  }

  openSession(session: SessionEntry): void {
    // Validação de entrada
    if (!session || !(session instanceof SessionEntry)) {
      throw new TypeError("session must be a SessionEntry instance");
    }
    if (!session.indexInfo) {
      throw new Error("Session must have valid indexInfo");
    }

    if (!this.isClosed(session)) {
      if (process.env.NODE_ENV !== 'production') {
        console.warn("Session already open");
      }
      return;
    }

    if (process.env.NODE_ENV !== 'production') {
      const baseKeyPreview = session.indexInfo.baseKey
        ? session.indexInfo.baseKey.toString('base64').substring(0, 8) + '...'
        : 'unknown';
      console.debug(`Opening session with baseKey: ${baseKeyPreview}`);
    }

    session.indexInfo.closed = -1;
  }

  isClosed(session: SessionEntry): boolean {
    if (!session || !(session instanceof SessionEntry)) {
      return true;
    }
    if (!session.indexInfo) {
      return true;
    }
    return session.indexInfo.closed !== -1;
  }

  removeOldSessions(): void {
    const sessionCount = Object.keys(this.sessions).length;

    if (sessionCount <= CLOSED_SESSIONS_MAX) {
      return;
    }


    const closedSessions: Array<{ key: string, session: SessionEntry, closedTime: number }> = [];

    for (const [key, session] of Object.entries(this.sessions)) {
      if (!session || !(session instanceof SessionEntry)) {
        continue;
      }
      if (session.indexInfo?.closed && session.indexInfo.closed !== -1) {
        closedSessions.push({
          key,
          session,
          closedTime: session.indexInfo.closed
        });
      }
    }

    // Se não há sessões fechadas suficientes, não podemos remover
    if (closedSessions.length === 0) {
      // Todas as sessões estão abertas - não podemos remover nenhuma
      if (process.env.NODE_ENV !== 'production') {
        console.warn(`Cannot remove old sessions: ${sessionCount} sessions but all are open`);
      }
      return;
    }

    // Ordenar por tempo de fechamento (mais antigas primeiro)
    closedSessions.sort((a, b) => a.closedTime - b.closedTime);

    // Remover sessões antigas até ficar com CLOSED_SESSIONS_MAX
    const toRemove = sessionCount - CLOSED_SESSIONS_MAX;
    const actualToRemove = Math.min(toRemove, closedSessions.length);

    for (let i = 0; i < actualToRemove; i++) {
      const { key, session } = closedSessions[i];

      if (process.env.NODE_ENV !== 'production') {
        const closedDate = new Date(session.indexInfo.closed).toISOString();
        console.debug(`Removing old closed session (closed at: ${closedDate})`);
      }

      secureDestroySession(session);
      delete this.sessions[key];
    }
  }

  deleteAllSessions(): void {
    for (const session of Object.values(this.sessions)) {
      secureDestroySession(session);
    }
    // Limpar o objeto
    this.sessions = {};
    if (process.env.NODE_ENV !== 'production') {
      console.debug("All sessions deleted");
    }
  }

  /**
   * Retorna o número total de sessões
   */
  getSessionCount(): number {
    return Object.keys(this.sessions).length;
  }

  /**
   * Retorna o número de sessões abertas
   */
  getOpenSessionCount(): number {
    let count = 0;
    for (const session of Object.values(this.sessions)) {
      if (session instanceof SessionEntry && !this.isClosed(session)) {
        count++;
      }
    }
    return count;
  }

  /**
   * Retorna o número de sessões fechadas
   */
  getClosedSessionCount(): number {
    let count = 0;
    for (const session of Object.values(this.sessions)) {
      if (session instanceof SessionEntry && this.isClosed(session)) {
        count++;
      }
    }
    return count;
  }

  /**
   * Limpa todos os dados sensíveis e destrói o registro
   */
  destroy(): void {
    this.deleteAllSessions();
    this.version = '';
  }
}