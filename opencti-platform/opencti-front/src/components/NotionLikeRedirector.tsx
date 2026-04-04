import { ReactNode } from 'react';
import { Navigate, useParams } from 'react-router-dom';

export interface NotionLikePageInfo {
  path: string;
}

interface NotionLikeRedirectorProps {
  /** Render prop triggered when a page matches current splat value **/
  renderMatch: (pageInfo: NotionLikePageInfo) => ReactNode;
  /** Component to render when no page matches **/
  NoMatch: ReactNode;
  /**
   * An object mapping pages' `id`s to a `NotionLikePageInfo`
   * that is passed back in the render prop upon match.
   */
  pagesInfo: Record<string, NotionLikePageInfo>;
}

/**
 * Routing utility that acts on routes ending with a splat ('*')
 * to provide a behaviour similar to Notion pages where a page is
 * accessible via a path formed by a slug and an id (`/[slug]-[id]`),
 * but where providing the correct slug part is not mandatory.
 * When the slug part is wrong the redirector redirects to the correct path.
 * This behaviour allows having human-friendly URLs while allowing
 * changing the page's title (& slug) without the fear of breaking links
 * containing previous versions of the slug.
 * Important constraint for this to work: the `id` part of the path must
 * not contain any hyphens.
 *
 * @example
 * ```
 * <Routes>
 *  <Route path='*' element={
 *    <NotionLikeRedirector
 *      renderMatch={({ path }) => `Matched on ${path}`}
 *      NoMatch="No match :("
 *      pagesInfo={{
 *        'dc6049d4e3fd436b9ed1956c4670517a': {
 *          path: 'a-great-page-dc6049d4e3fd436b9ed1956c4670517a',
 *        },
 *        '73f7840b2b4d444c861bd6a18b9e6d66': {
 *          path: 'another-great-page-73f7840b2b4d444c861bd6a18b9e6d66',
 *        },
 *      }}
 *  } />
 * </Routes>
 * ```
 */
const NotionLikeRedirector = ({ renderMatch, NoMatch, pagesInfo }: NotionLikeRedirectorProps) => {
  const { '*': splat } = useParams();
  if (!splat) {
    return NoMatch;
  }
  let firstSegmentEnd = splat.indexOf('/');
  firstSegmentEnd = firstSegmentEnd < 0 ? splat.length : firstSegmentEnd;
  const segment = splat.substring(0, firstSegmentEnd);
  const dashPos = segment.lastIndexOf('-');
  if (dashPos < 0) {
    return NoMatch;
  }
  const id = segment.substring(dashPos + 1);
  const pageInfo = pagesInfo[id];
  if (!pageInfo) {
    return NoMatch;
  }
  if (pageInfo.path !== segment) {
    return <Navigate to={pageInfo.path} />;
  }
  return renderMatch(pageInfo);
};

export default NotionLikeRedirector;
