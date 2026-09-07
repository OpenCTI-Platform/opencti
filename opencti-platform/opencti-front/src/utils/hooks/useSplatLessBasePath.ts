import { useContext } from 'react';
import { UNSAFE_RouteContext } from 'react-router-dom';

/**
 * Base path of the closest matched route, without its splat part nor trailing
 * slash. Since v7, relative targets resolve against the whole location, splat
 * included, so links and redirects under a splat route must be built on this.
 * Read from the route context rather than derived from the url so it stays
 * correct wherever the consumer sits in the router.
 */
const useSplatLessBasePath = (): string => {
  const { matches } = useContext(UNSAFE_RouteContext);
  const base = matches[matches.length - 1]?.pathnameBase ?? '/';
  return base.replace(/\/$/, '');
};

export default useSplatLessBasePath;
