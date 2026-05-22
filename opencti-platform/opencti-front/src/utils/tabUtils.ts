/**
 * Compute the current state value of a <Tabs> component by comparing the
 * location.pathname (`fullpath`) with the `basePath` of the component
 * and extracting the next URL segment in the sequence.
 *
 * @param fullpath - The current full pathname as returned by useLocation().pathname.
 * Should contain no query params nor hash param.
 * @param basePath - The closest path to root where the <Tabs> component is rendered.
 * @returns The current tab value.
 *
 * @example
 * ```
 * getCurrentTab(
 *   '/dashboard/techniques/attack_patterns/965f2989-6acb-4223-a163-89a99411c15c/knowledge/or/something/else',
 *   '/dashboard/techniques/attack_patterns/965f2989-6acb-4223-a163-89a99411c15c',
 * ); // returns 'knowledge'
 * ```
 */
export const getCurrentTab = (fullpath: string, basePath: string) => {
  let subpath = fullpath.substring(basePath.length);
  if (subpath.startsWith('/')) {
    subpath = subpath.substring(1);
  }
  const nextSlashPos = subpath.indexOf('/');
  return nextSlashPos >= 0 ? subpath.substring(0, nextSlashPos) : subpath;
};

/**
 * Determines whether the current location corresponds to the overview page.
 * The overview page can be either at the base path (before redirect) or at basePath/overview.
 *
 * @param locationPath The current location pathname.
 * @param basePath The entity base path.
 * @returns True if the current path is the overview page.
 */
export const isPathOverview = (locationPath: string, basePath: string): boolean => {
  return locationPath === basePath || locationPath === `${basePath}/overview`;
};
