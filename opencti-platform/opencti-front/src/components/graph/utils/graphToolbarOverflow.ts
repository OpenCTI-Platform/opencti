/** An action of the graph toolbar that can move to its "More actions" menu. */
export interface ToolbarOverflowCandidate {
  id: string;
  /** Actions of a group sit together, after a divider. */
  group: string;
  /** Higher stays in the toolbar longer; 0 or less always goes to the "More actions" menu. */
  priority: number;
  /** A toggle in effect keeps its place before the others: it is turned off where it was turned on. */
  pressed?: boolean;
}

export interface ToolbarMetrics {
  /** Room taken by one icon button and the gap after it. */
  action: number;
  /** Room taken by the divider opening a group. */
  divider: number;
}

/** A medium design-system icon button (36 px) and the toolbar gap after it. */
export const TOOLBAR_ACTION_WIDTH = 40;
/** A vertical divider with its margins and the toolbar gap after it. */
export const TOOLBAR_DIVIDER_WIDTH = 21;

const DEFAULT_METRICS: ToolbarMetrics = { action: TOOLBAR_ACTION_WIDTH, divider: TOOLBAR_DIVIDER_WIDTH };

/**
 * The actions drawn in the toolbar within the room the pinned parts leave, the toggles in effect
 * then the most important first; the others are listed in the "More actions" menu. Rare actions
 * (priority 0) always are.
 * An unmeasured toolbar (`room` not finite) draws every action that is not rare.
 */
export const planToolbarOverflow = (
  candidates: readonly ToolbarOverflowCandidate[],
  room: number,
  metrics: ToolbarMetrics = DEFAULT_METRICS,
): Set<string> => {
  const eligible = candidates
    .map((candidate, index) => ({ candidate, index }))
    .filter(({ candidate }) => candidate.priority > 0);
  if (!Number.isFinite(room)) return new Set(eligible.map(({ candidate }) => candidate.id));
  const shown = new Set<string>();
  const openGroups = new Set<string>();
  let used = 0;
  eligible
    .sort((a, b) => Number(!!b.candidate.pressed) - Number(!!a.candidate.pressed)
      || b.candidate.priority - a.candidate.priority
      || a.index - b.index)
    .forEach(({ candidate }) => {
      const cost = metrics.action + (openGroups.has(candidate.group) ? 0 : metrics.divider);
      if (used + cost > room) return;
      used += cost;
      shown.add(candidate.id);
      openGroups.add(candidate.group);
    });
  return shown;
};

/** Room the creation and removal tools take once folded: their divider and one button. */
export const FOLDED_CREATION_WIDTH = TOOLBAR_DIVIDER_WIDTH + TOOLBAR_ACTION_WIDTH;

/**
 * Whether the creation and removal tools, which stay in the toolbar while the other actions move
 * to "More actions", fold into one button: when the room left by the other fixed parts cannot
 * hold them, the row would clip them. Folded, they come back once the room holds them with an
 * action to spare, so a width at the threshold does not make them flicker. An unmeasured toolbar
 * (`available` not finite) or tools not measured yet never fold.
 */
export const shouldFoldCreationTools = (available: number, creationWidth: number, folded: boolean): boolean => {
  if (!Number.isFinite(available) || creationWidth <= 0) return false;
  return folded ? available < creationWidth + TOOLBAR_ACTION_WIDTH : available < creationWidth;
};
