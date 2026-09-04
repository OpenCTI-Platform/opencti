import { ReactNode } from 'react';
import { Navigate, useParams } from 'react-router-dom';

const EXTRACT_UUID_FROM_SEGMENT = (segment: string) => {
  const results = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.exec(segment);
  if (results && results[0]) {
    return results[0];
  }
  return null;
};

export interface SlugRedirectHandlerPageInfo {
  path: string;
}

interface SlugRedirectHandlerProps {
  /** Render prop triggered when a page matches current splat value **/
  renderMatch: (pageInfo: SlugRedirectHandlerPageInfo) => ReactNode;
  /** Component to render when no page matches **/
  NoMatch: ReactNode;
  /**
   * An object mapping pages' `id`s to a `SlugRedirectHandlerPageInfo`
   * that is passed back in the render prop upon match.
   */
  pagesInfo: Record<string, SlugRedirectHandlerPageInfo>;
  /**
   * Strategy to extract page id (index of `pagesInfo`) from the URL segment.
   * Ex: extract id `dc6049d4-e3fd-436b-9ed1-956c4670517a` from
   * segment `a-great-page-dc6049d4-e3fd-436b-9ed1-956c4670517a`.
   * Default strategy handles UUIDs with hyphens.
   */
  extractPageIdFromSegment?: (segment: string) => string | null;
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
 *    <SlugRedirectHandler
 *      renderMatch={({ path }) => `Matched on ${path}`}
 *      NoMatch="No match :("
 *      pagesInfo={{
 *        'dc6049d4-e3fd-436b-9ed1-956c4670517a': {
 *          path: 'a-great-page-dc6049d4-e3fd-436b-9ed1-956c4670517a',
 *        },
 *        '73f7840b-2b4d-444c-861b-d6a18b9e6d66': {
 *          path: 'another-great-page-73f7840b-2b4d-444c-861b-d6a18b9e6d66',
 *        },
 *      }}
 *  } />
 * </Routes>
 * ```
 */
const SlugRedirectHandler = ({
  renderMatch,
  NoMatch,
  pagesInfo,
  extractPageIdFromSegment = EXTRACT_UUID_FROM_SEGMENT,
}: SlugRedirectHandlerProps) => {
  const { '*': splat } = useParams();
  if (!splat) {
    return NoMatch;
  }
  let firstSegmentEnd = splat.indexOf('/');
  firstSegmentEnd = firstSegmentEnd < 0 ? splat.length : firstSegmentEnd;
  const segment = splat.substring(0, firstSegmentEnd);
  const id = extractPageIdFromSegment(segment);
  if (id === null) {
    return NoMatch;
  }
  const pageInfo = pagesInfo[id];
  if (!pageInfo) {
    return NoMatch;
  }
  if (pageInfo.path !== segment) {
    return <Navigate to={pageInfo.path} />;
  }
  return renderMatch(pageInfo);
};

export default SlugRedirectHandler;
