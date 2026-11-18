import { useFormatter } from '../../../components/i18n';
import useVisibleEntries from '../common/menus/useVisibleEntries';
import useNavMenu from './useNavMenu';
import { allMenuEntries } from './menuEntries';

export interface NavSearchResult {
  path: string;
  label: string;
  /** Labels of the parent pages, e.g. ['Data', 'Import'] */
  parents: string[];
  /** Why the page matches when the displayed label and breadcrumb do not say it: the matched keywords / English breadcrumb words. */
  hints?: string[];
}

/**
 * `names`: the page label, in the user language and in English. Besides its (translated) `parents`, a page is found by
 * its `keywords` (user language first, then English) and its English `breadcrumb`. Entries may be undefined (no English
 * label known).
 */
type Node = Omit<NavSearchResult, 'hints'> & {
  names: (string | undefined)[];
  keywords: (string | undefined)[];
  breadcrumb: (string | undefined)[];
};

/** Consumers display at most this many pages: the hook returns them all so they can tell when the list is cut. */
export const PLATFORM_SEARCH_PAGE_MAX_RESULTS = 10;

// Case and accent insensitive: labels are translated, "parametres" must find "Paramètres".
const fold = (text: string) => text.normalize('NFD').replace(/\p{Diacritic}/gu, '').toLowerCase();
// "&" stays inside a word ("c&c", "att&ck"); a lone "&" is not a word. `folded` is what is compared, `shown` what a
// hint displays: lower case (keywords reuse the casing of the translation keys) but with its accents.
const words = (text: string) => text
  .split(/[^\p{L}\p{N}\p{M}&]+/u)
  .filter((word) => /[\p{L}\p{N}]/u.test(word))
  .map((word) => ({ folded: fold(word), shown: word.toLowerCase() }));

const useNavSearch = (keyword?: string | null): NavSearchResult[] => {
  const { t_i18n } = useFormatter();
  const navGroups = useNavMenu();
  const entries = useVisibleEntries(allMenuEntries);

  const tokens = words(keyword ?? '').map(({ folded }) => folded);
  if (tokens.length === 0) return [];

  // Left bar: already filtered by permissions and hidden entities. Translation keys are the English texts, so the
  // English label/keywords are searched too: a user can type the English name whatever the platform language.
  const navNodes: Node[] = navGroups.flatMap((group) => group.items.flatMap((item) => [
    { path: item.link, label: item.label, parents: [], names: [item.label, item.englishLabel], keywords: item.keywords ?? [], breadcrumb: [] },
    ...(item.subItems ?? []).map((sub) => ({
      path: sub.link,
      label: sub.label,
      parents: [item.label],
      names: [sub.label, sub.englishLabel],
      keywords: sub.keywords ?? [],
      breadcrumb: [item.englishLabel],
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
        keywords,
        breadcrumb: standaloneParents,
      }];
    }
    const section = sectionOf(entry.path);
    if (!section) return [];
    return [{
      path: entry.path,
      label: names[0],
      parents: [...section.parents, section.label],
      names,
      keywords,
      breadcrumb: section.english,
    }];
  });

  const byPath = new Map<string, Node>();
  [...navNodes, ...entryNodes].forEach((node) => byPath.set(node.path, node));

  // Every typed word must start a word of the page: of its label (rank 0), or of its breadcrumb / keywords (rank 1).
  // A word found only in the English label, a keyword or the English breadcrumb is not visible in the result: it comes
  // back as a hint (in the language typed: the pools are ordered user language first).
  const match = (node: Node): { rank: number; hints: string[] } | undefined => {
    const folded = (text: (string | undefined)[]) => words(text.join(' ')).map((w) => w.folded);
    const visible = [...folded(node.names.slice(0, 1)), ...folded(node.parents)];
    const hidden = words([...node.names.slice(1), ...node.keywords, ...node.breadcrumb].join(' '));
    const hints = new Set<string>();
    const found = tokens.every((token) => {
      if (visible.some((w) => w.startsWith(token))) return true;
      const hit = hidden.find((w) => w.folded.startsWith(token));
      if (hit) hints.add(hit.shown);
      return !!hit;
    });
    if (!found) return undefined;
    const names = folded(node.names);
    return { rank: tokens.every((token) => names.some((w) => w.startsWith(token))) ? 0 : 1, hints: [...hints] };
  };
  return [...byPath.values()]
    .flatMap((node) => {
      const result = match(node);
      return result ? [{ node, ...result }] : [];
    })
    .sort((a, b) => a.rank - b.rank)
    .map(({ node: { path, label, parents }, hints }) => (hints.length > 0 ? { path, label, parents, hints } : { path, label, parents }));
};

export default useNavSearch;
