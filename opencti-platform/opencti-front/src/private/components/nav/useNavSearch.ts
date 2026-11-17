import { useFormatter } from '../../../components/i18n';
import useVisibleEntries from '../common/menus/useVisibleEntries';
import useNavMenu from './useNavMenu';
import { allMenuEntries } from './menuEntries';

export interface NavSearchResult {
  path: string;
  label: string;
  /** Labels of the parent pages, e.g. ['Data', 'Import'] */
  parents: string[];
}

type Node = NavSearchResult & { keywords: string[] };

/** Consumers display at most this many pages: the hook returns them all so they can tell when the list is cut. */
export const PLATFORM_SEARCH_PAGE_MAX_RESULTS = 10;

// Case and accent insensitive: labels are translated, "parametres" must find "Paramètres".
const fold = (text: string) => text.normalize('NFD').replace(/\p{Diacritic}/gu, '').toLowerCase();

const useNavSearch = (keyword?: string | null): NavSearchResult[] => {
  const { t_i18n } = useFormatter();
  const navGroups = useNavMenu();
  const entries = useVisibleEntries(allMenuEntries);

  const tokens = fold(keyword ?? '').split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return [];

  // Left bar: already filtered by permissions and hidden entities.
  const navNodes: Node[] = navGroups.flatMap((group) => group.items.flatMap((item) => [
    { path: item.link, label: item.label, parents: [], keywords: item.keywords ?? [] },
    ...(item.subItems ?? []).map((sub) => ({ path: sub.link, label: sub.label, parents: [item.label], keywords: sub.keywords ?? [] })),
  ]));

  // Page entries must belong to a visible left bar subsection (its own permission, hidden in draft, etc.): it also
  // gives the breadcrumb. No visible subsection = the entry is not reachable, so not indexed.
  const sectionNodes = navGroups.flatMap((group) => group.items.flatMap((item) => (
    (item.subItems ?? []).flatMap((sub) => (sub.paths ? [{ paths: sub.paths, label: sub.label, parents: [item.label] }] : []))
  )));
  const sectionOf = (path: string) => sectionNodes.find((n) => n.paths.includes(path));
  const entryNodes: Node[] = entries.flatMap((entry) => {
    const keywords = (entry.keywords ?? []).map((keyword) => t_i18n(keyword));
    if (entry.standaloneParents) {
      return [{ path: entry.path, label: t_i18n(entry.label), parents: entry.standaloneParents.map((p) => t_i18n(p)), keywords }];
    }
    const section = sectionOf(entry.path);
    if (!section) return [];
    return [{
      path: entry.path,
      label: t_i18n(entry.label),
      parents: [...section.parents, section.label],
      keywords,
    }];
  });

  const byPath = new Map<string, Node>();
  [...navNodes, ...entryNodes].forEach((node) => byPath.set(node.path, node));

  const matchRank = (node: Node) => {
    const label = fold(node.label);
    const haystack = fold([node.label, ...node.parents, ...node.keywords].join(' '));
    if (!tokens.every((token) => haystack.includes(token))) return -1;
    return tokens.every((token) => label.includes(token)) ? 0 : 1;
  };
  return [...byPath.values()]
    .map((node) => ({ node, rank: matchRank(node) }))
    .filter(({ rank }) => rank >= 0)
    .sort((a, b) => a.rank - b.rank)
    .map(({ node: { path, label, parents } }) => ({ path, label, parents }));
};

export default useNavSearch;
