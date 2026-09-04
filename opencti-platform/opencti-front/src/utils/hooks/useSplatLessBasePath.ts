import { useContext } from 'react';
import { UNSAFE_RouteContext } from 'react-router-dom';

/**
 * Base path of the closest matched route: its pathname without any splat part,
 * and without a trailing slash.
 *
 * react-router v7 resolves relative targets against the whole matched
 * location, splat included (v6 resolved them against the route's base). A
 * relative <Link> or <Navigate> under a splat route therefore appends to the
 * current segment instead of replacing it: from /reports/R1/overview, a bare
 * 'observables' now yields /reports/R1/overview/observables, which matches no
 * route -- and an empty target no longer goes back to the base at all. Links
 * and redirects rendered under a splat route must be absolute, built on this
 * base (or on an equivalent one already known by the component).
 *
 * The value is read from the route context (`pathnameBase` of the closest
 * match), the same one the router uses to mount descendant <Routes>. It is
 * positional by construction: it stays correct wherever the component sits in
 * the router -- under a splat, under nested children or on an exact route --
 * unlike any computation made from the url. UNSAFE_RouteContext is the
 * documented escape hatch for this and only breaks loudly, at build time, on
 * a major upgrade; deriving the base from the pathname instead would silently
 * return a wrong value the day a consumer is moved off a splat route.
 */
const useSplatLessBasePath = (): string => {
  const { matches } = useContext(UNSAFE_RouteContext);
  const base = matches[matches.length - 1]?.pathnameBase ?? '/';
  return base.replace(/\/$/, '');
};

export default useSplatLessBasePath;
