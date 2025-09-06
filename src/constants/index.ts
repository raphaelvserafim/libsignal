export const CLOSED_SESSIONS_MAX = 40;

export const SESSION_RECORD_VERSION = 'v1';


export const migrations = [{
  version: 'v1',
  migrate: function migrateV1(data: {
    _sessions: { [key: string]: { registrationId: string; indexInfo: { closed: number } } };
    registrationId: string;
    version: string
  }) {
    const sessions = data._sessions;
    if (data.registrationId) {
      for (const key in sessions) {
        if (!sessions[key].registrationId) {
          sessions[key].registrationId = data.registrationId;
        }
      }
    } else {
      for (const key in sessions) {
        if (sessions[key].indexInfo.closed === -1) {
          console.error('V1 session storage migration error: registrationId',
            data.registrationId, 'for open session version',
            data.version);
        }
      }
    }
  }
}];