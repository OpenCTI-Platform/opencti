import { createContext, useContext } from 'react';

// Integer incremented on every manual or auto refresh in CustomDashboard.
// In DashboardContent, the provider passes a number token (0, 1, 2, ...)
// so useDashboardViz relies on this central refresh source.
// Outside this provider, the value is null to signal there is no dashboard-level
// token source and widget-level interval fallback can be used.
const DashboardRefreshContext = createContext<number | null>(null);

export const useDashboardRefreshToken = () => useContext(DashboardRefreshContext);

export default DashboardRefreshContext;
