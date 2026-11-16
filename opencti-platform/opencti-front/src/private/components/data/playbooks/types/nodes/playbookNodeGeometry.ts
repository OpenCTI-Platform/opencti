import type { XYPosition } from 'reactflow';
import type { PlaybookLayoutDirection } from '../../hooks/usePlaybookLayoutMode';
import type { Theme } from '../../../../../../components/Theme';

// The identity colour of each family of components, from the design system tokens.
export const categoryAccent = (theme: Theme, category: string | null | undefined): string => {
  const { tertiary, primary } = theme.palette.designSystem;
  switch (category) {
    case 'start_playbook':
      return primary.main;
    case 'share_and_access':
      return tertiary.orange?.[500] ?? primary.main;
    case 'end_playbook':
      return tertiary.green?.[400] ?? primary.main;
    default:
      return tertiary.darkBlue?.[300] ?? primary.main;
  }
};

// The arrowhead of the links: defined once by the canvas, referenced by every link.
export const PLAYBOOK_ARROW_ID = 'playbook-link-arrow';

// One size for every step card: the layout reserves exactly the room the card draws.
export const PLAYBOOK_CARD = { width: 264, height: 104 };
// The add button of a free out port, drawn just past the port it extends: close to the card, so it
// stays clear of the middle line of the rank gap, where the links of a neighbouring step turn.
export const PLAYBOOK_PORT_ADD = { size: 28, gap: 16 };

type Port = { id: string; type: string };

export const outPorts = (ports: ReadonlyArray<Port | null | undefined> | null | undefined): Port[] => {
  return (ports ?? []).flatMap((p) => (p && p.type === 'out' ? [p] : []));
};

// The top of the right edge holds the three-dot menu of the card: in the horizontal layout, the
// labelled ports of a step with several of them share the edge below it, so no pill covers the menu.
export const PLAYBOOK_CARD_MENU_BAND = 36;

// Where the out port number `index` of `count` sits on the card edge, relative to the card corner.
export const portAnchor = (index: number, count: number, direction: PlaybookLayoutDirection): XYPosition => {
  const safeCount = Math.max(1, count);
  if (direction === 'horizontal') {
    const top = safeCount > 1 ? PLAYBOOK_CARD_MENU_BAND : 0;
    const interval = (PLAYBOOK_CARD.height - top) / safeCount;
    return { x: PLAYBOOK_CARD.width, y: Math.round(top + index * interval + interval / 2) };
  }
  const interval = PLAYBOOK_CARD.width / safeCount;
  return { x: index * interval + interval / 2, y: PLAYBOOK_CARD.height };
};

// Top-left corner of the add button of a free port, from the top-left corner of its card.
export const portAddPosition = (card: XYPosition, index: number, count: number, direction: PlaybookLayoutDirection): XYPosition => {
  const anchor = portAnchor(index, count, direction);
  const half = PLAYBOOK_PORT_ADD.size / 2;
  if (direction === 'horizontal') {
    return { x: card.x + anchor.x + PLAYBOOK_PORT_ADD.gap, y: card.y + anchor.y - half };
  }
  return { x: card.x + anchor.x - half, y: card.y + anchor.y + PLAYBOOK_PORT_ADD.gap };
};
