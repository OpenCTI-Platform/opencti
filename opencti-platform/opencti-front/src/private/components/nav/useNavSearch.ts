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

/**
 * `names`: the page label, in the user language and in English. `context`: what else finds the page besides its
 * (translated) `parents`: English breadcrumb and keywords. Entries may be undefined (no English label known).
 */
type Node = NavSearchResult & { names: (string | undefined)[]; context: (string | undefined)[] };

/** Consumers display at most this many pages: the hook returns them all so they can tell when the list is cut. */
export const PLATFORM_SEARCH_PAGE_MAX_RESULTS = 10;

// Case and accent insensitive: labels are translated, "parametres" must find "Paramètres".
const fold = (text: string) => text.normalize('NFD').replace(/\p{Diacritic}/gu, '').toLowerCase();
// "&" stays inside a word ("c&c", "att&ck"); a lone "&" is not a word.
const words = (text: string) => fold(text).split(/[^\p{L}\p{N}&]+/u).filter((word) => /[\p{L}\p{N}]/u.test(word));

const useNavSearch = (keyword?: string | null): NavSearchResult[] => {
  const { t_i18n } = useFormatter();
  const navGroups = useNavMenu();
  const entries = useVisibleEntries(allMenuEntries);

  const tokens = words(keyword ?? '');
  if (tokens.length === 0) return [];

  // Left bar: already filtered by permissions and hidden entities. Translation keys are the English texts, so the
  // English label/keywords are searched too: a user can type the English name whatever the platform language.
  const navNodes: Node[] = navGroups.flatMap((group) => group.items.flatMap((item) => [
    { path: item.link, label: item.label, parents: [], names: [item.label, item.englishLabel], context: item.keywords ?? [] },
    ...(item.subItems ?? []).map((sub) => ({
      path: sub.link,
      label: sub.label,
      parents: [item.label],
      names: [sub.label, sub.englishLabel],
      context: [item.englishLabel, ...(sub.keywords ?? [])],
    })),
  ]));

  // Page entries must belong to a visible left bar subsection (its own permission, hidden in draft, etc.): it also
  // gives the breadcrumb. No visible subsection = the entry is not reachable, so not indexed.
  const sectionNodes = navGroups.flatMap((group) => group.items.flatMap((item) => (
    (item.subItems ?? []).flatMap((sub) => (sub.paths
      ? [{ paths: sub.paths, label: sub.label, parents: [item.label], english: [item.englishLabel, sub.englishLabel] }]
      : []))
  )));
  const sectionOf = (path: string) => sectionNodes.find((n) => n.paths.includes(path));
  const entryNodes: Node[] = entries.flatMap((entry) => {
    const keywords = (entry.keywords ?? []).flatMap((k) => [t_i18n(k), k]);
    const names = [t_i18n(entry.label), entry.label];
    if (entry.standaloneParents) {
      const { standaloneParents } = entry;
      return [{
        path: entry.path,
        label: names[0],
        parents: standaloneParents.map((p) => t_i18n(p)),
        names,
        context: [...standaloneParents, ...keywords],
      }];
    }
    const section = sectionOf(entry.path);
    if (!section) return [];
    return [{
      path: entry.path,
      label: names[0],
      parents: [...section.parents, section.label],
      names,
      context: [...section.english, ...keywords],
    }];
  });

  const byPath = new Map<string, Node>();
  [...navNodes, ...entryNodes].forEach((node) => byPath.set(node.path, node));

  // Every typed word must start a word of the page: of its label (rank 0), or of its breadcrumb / keywords (rank 1).
  const startsAWord = (pool: string[]) => tokens.every((token) => pool.some((w) => w.startsWith(token)));
  const matchRank = (node: Node) => {
    const nameWords = words(node.names.join(' '));
    if (startsAWord(nameWords)) return 0;
    return startsAWord([...nameWords, ...words([...node.parents, ...node.context].join(' '))]) ? 1 : -1;
  };
  return [...byPath.values()]
    .map((node) => ({ node, rank: matchRank(node) }))
    .filter(({ rank }) => rank >= 0)
    .sort((a, b) => a.rank - b.rank)
    .map(({ node: { path, label, parents } }) => ({ path, label, parents }));
};

export default useNavSearch;
