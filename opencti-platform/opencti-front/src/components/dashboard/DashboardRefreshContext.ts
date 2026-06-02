import { createContext, useContext } from 'react';

// Integer incremented on every manual or auto refresh in CustomDashboard.
// Passed via context so useDashboardViz can react to it without requiring every
// intermediate component (DashboardContent → DashboardViz → widget) to thread it as a prop.
const DashboardRefreshContext = createContext<number>(0);

export const useDashboardRefreshToken = () => useContext(DashboardRefreshContext);

export default DashboardRefreshContext;
