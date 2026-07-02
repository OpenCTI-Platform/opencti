import { createContext, PropsWithChildren, useCallback, useContext, useMemo, useState } from 'react';

interface DashboardRefreshContextValue {
  // Integer incremented on every manual or auto refresh, so useDashboardViz can
  // rely on this central refresh source. null when there is no dashboard-level
  // refresh provider, signalling widgets to use their interval fallback instead.
  refreshToken: number | null;
  // True while at least one widget query is still in flight.
  isRefreshing: boolean;
  // Called by each widget to register/unregister its query as pending.
  setQueryPending: (queryId: string, isPending: boolean) => void;
}

const DashboardRefreshContext = createContext<DashboardRefreshContextValue>({
  refreshToken: null,
  isRefreshing: false,
  // No-op until a DashboardRefreshProvider supplies the real implementation.
  setQueryPending: () => {},
});

export const useDashboardRefreshToken = () => useContext(DashboardRefreshContext).refreshToken;

export const useDashboardRefreshPendingState = () => useContext(DashboardRefreshContext).isRefreshing;

export const useDashboardSetQueryPending = () => useContext(DashboardRefreshContext).setQueryPending;

interface DashboardRefreshProviderProps {
  refreshToken?: number | null;
}

export const DashboardRefreshProvider = ({
  refreshToken = null,
  children,
}: PropsWithChildren<DashboardRefreshProviderProps>) => {
  const [pendingQueryIds, setPendingQueryIds] = useState<Set<string>>(new Set());

  const setQueryPending = useCallback((queryId: string, isPending: boolean) => {
    setPendingQueryIds((previous) => {
      if (isPending === previous.has(queryId)) {
        return previous;
      }
      const next = new Set(previous);
      if (isPending) {
        next.add(queryId);
      } else {
        next.delete(queryId);
      }
      return next;
    });
  }, []);

  const value = useMemo<DashboardRefreshContextValue>(() => ({
    refreshToken,
    isRefreshing: pendingQueryIds.size > 0,
    setQueryPending,
  }), [refreshToken, pendingQueryIds, setQueryPending]);

  return (
    <DashboardRefreshContext.Provider value={value}>
      {children}
    </DashboardRefreshContext.Provider>
  );
};

export default DashboardRefreshContext;
