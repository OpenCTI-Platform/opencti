import { createContext, PropsWithChildren, useCallback, useContext, useRef, useSyncExternalStore } from 'react';

type DashboardPendingStateStore = {
  getSnapshot: () => boolean;
  subscribe: (listener: () => void) => () => void;
};

// Split refresh concerns so high-frequency pending updates do not fan out to
// all refresh-token consumers (widgets).
// - refresh token: changes when user/auto refresh is triggered
// - setQueryPending: stable callback widgets call while queries start/finish
// - pending state store: consumed by refresh control only
const DashboardRefreshTokenContext = createContext<number | null>(null);

const DashboardSetQueryPendingContext = createContext<(
  queryId: string,
  isPending: boolean,
) => void>(() => {});

const DashboardPendingStateContext = createContext<DashboardPendingStateStore>({
  getSnapshot: () => false,
  subscribe: () => () => {},
});

export const useDashboardRefreshToken = () => useContext(DashboardRefreshTokenContext);

export const useDashboardSetQueryPending = () => useContext(DashboardSetQueryPendingContext);

export const useDashboardRefreshPendingState = () => {
  const pendingStateStore = useContext(DashboardPendingStateContext);
  // useSyncExternalStore subscribes only to the pending-state store and updates
  // this consumer when the store snapshot changes. This keeps widget trees that
  // only need refreshToken from re-rendering on every query pending flip.
  return useSyncExternalStore(
    pendingStateStore.subscribe,
    pendingStateStore.getSnapshot,
    pendingStateStore.getSnapshot,
  );
};

interface DashboardRefreshProviderProps {
  refreshToken?: number | null;
}

export const DashboardRefreshProvider = ({
  refreshToken = null,
  children,
}: PropsWithChildren<DashboardRefreshProviderProps>) => {
  // Keep mutable pending data in refs so widget pending transitions can be
  // tracked without triggering a React context value change each time.
  const pendingQueryIdsRef = useRef<Set<string>>(new Set());
  const isRefreshingRef = useRef(false);
  const pendingListenersRef = useRef<Set<() => void>>(new Set());

  const pendingStateStoreRef = useRef<DashboardPendingStateStore>({
    getSnapshot: () => isRefreshingRef.current,
    subscribe: (listener) => {
      pendingListenersRef.current.add(listener);
      return () => {
        pendingListenersRef.current.delete(listener);
      };
    },
  });

  const setQueryPending = useCallback((queryId: string, isPending: boolean) => {
    const pendingQueryIds = pendingQueryIdsRef.current;
    if (isPending === pendingQueryIds.has(queryId)) {
      return;
    }

    if (isPending) {
      pendingQueryIds.add(queryId);
    } else {
      pendingQueryIds.delete(queryId);
    }

    // Notify only when aggregate state flips (false->true or true->false).
    // This prevents the "one widget settles -> whole dashboard re-renders"
    // storm that caused flaky toolbar/menu interactions in CI.
    const nextIsRefreshing = pendingQueryIds.size > 0;
    if (nextIsRefreshing === isRefreshingRef.current) {
      return;
    }

    isRefreshingRef.current = nextIsRefreshing;
    pendingListenersRef.current.forEach((listener) => listener());
  }, []);

  return (
    <DashboardRefreshTokenContext.Provider value={refreshToken}>
      <DashboardSetQueryPendingContext.Provider value={setQueryPending}>
        <DashboardPendingStateContext.Provider value={pendingStateStoreRef.current}>
          {children}
        </DashboardPendingStateContext.Provider>
      </DashboardSetQueryPendingContext.Provider>
    </DashboardRefreshTokenContext.Provider>
  );
};

export default DashboardRefreshTokenContext;
