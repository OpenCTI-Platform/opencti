import { useLocation } from 'react-router-dom';

/**
 * Hook to check if the current route is a public route (without authentication):
 *
 * @returns true if the current route is public, false otherwise
 *
 * @example
 * ```tsx
 * const isPublic = useIsPublicRoute();
 * if (isPublic) {
 *   // Handle public route logic
 * }
 * ```
 */
const useIsPublicRoute = (): boolean => {
  const location = useLocation();
  return location.pathname.startsWith('/public/');
};

export default useIsPublicRoute;
