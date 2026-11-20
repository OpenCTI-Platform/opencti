import type { ReactElement } from 'react';
import { Navigate } from 'react-router';
import useVisibleEntries from '../common/menus/useVisibleEntries';
import { entriesUnder } from './menuEntries';

interface EntryGuardProps {
  /** Page (or section, see `exact`) declared by a `*.entries.ts(x)` file. */
  path: string;
  /** Only this page, not the pages under it (a page that is also a section, like Parameters). */
  exact?: boolean;
  children: ReactElement;
  placeholder?: ReactElement | null;
}

/**
 * Route guard: renders `children` only if the page is visible to the user, by the same rules as the left bar and the
 * pages search (capabilities, feature flag, Enterprise Edition, draft). A section is open if one of its pages is.
 * An unknown path has no entry, so it is denied. A denied user is redirected to the dashboard unless `placeholder` says otherwise.
 */
const EntryGuard = ({ path, exact, children, placeholder = <Navigate to="/dashboard" replace={true} /> }: EntryGuardProps) => {
  const visible = useVisibleEntries(entriesUnder(path, { exact }), { ignoreHidden: true });
  return visible.length > 0 ? children : placeholder;
};

export default EntryGuard;
