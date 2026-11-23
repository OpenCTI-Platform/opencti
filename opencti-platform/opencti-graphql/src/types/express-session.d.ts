// express-session ships no types (and @types/express-session is not a dependency): only what the code uses is declared.
// The session itself, as seen from a request, is typed on Express.Request (express.d.ts).
declare module 'express-session' {
  // Also run outside express (websocket upgrade requests, with an empty response object)
  function session(options: session.SessionOptions): (req: unknown, res: unknown, next: (err?: unknown) => void) => void;

  namespace session {
    interface SessionOptions {
      store?: Store;
      secret: string | string[];
      name?: string;
      resave?: boolean;
      saveUninitialized?: boolean;
      rolling?: boolean;
      proxy?: boolean;
      cookie?: Record<string, unknown>;
    }
    type StoreCallback = (err?: unknown, session?: unknown) => void;
    // Base class of the session stores (SessionStoreMemory, RedisStore)
    class Store {
      constructor(options?: unknown);
    }
    // The in-memory store bundled with express-session, for tests
    class MemoryStore extends Store {
      get(sid: string, callback: StoreCallback): void;
      set(sid: string, session: unknown, callback?: (err?: unknown) => void): void;
      destroy(sid: string, callback?: (err?: unknown) => void): void;
    }
  }

  export default session;
}
