import { MutableRefObject, useCallback, useEffect, useLayoutEffect, useMemo, useState } from 'react';
import useResizeObserver from '../../../utils/hooks/useResizeObserver';
import { FOLDED_CREATION_WIDTH, shouldFoldCreationTools, TOOLBAR_GAP_PX } from './graphToolbarOverflow';
import { CREATION_SELECTOR, PINNED_SELECTOR, WIDE_CONTROL_ID_ATTRIBUTE, WIDE_CONTROL_SELECTOR } from '../components/ToolbarParts';

interface ToolbarRoomOptions {
  /** Horizontal padding of the row, both sides added. */
  padding: number;
  /** Whether the row has creation tools that can fold into one button. */
  hasFoldable: boolean;
  onFoldChange?: (folded: boolean) => void;
}

/**
 * Measures the toolbar row and returns the room left for the actions.
 *
 * Room = row width - padding - pinned parts - creation tools (or their folded button).
 *
 * It also decides whether the creation tools fold, and keeps the measured width of each
 * wide control (a select, a combobox). A wide control keeps its last width while it sits
 * in "More actions", so the plan knows when it fits back in the row.
 *
 * Widths of the pinned parts and wide controls are read before paint (layout effect).
 * The row width comes from a ResizeObserver, so it arrives after the first render:
 * until then the room is unknown and every action that is not rare is drawn.
 * The row elements are found through the selectors of `ToolbarParts`.
 */
const useToolbarRoom = (
  rowRef: MutableRefObject<HTMLDivElement | null>,
  { padding, hasFoldable, onFoldChange }: ToolbarRoomOptions,
) => {
  const { width: rowWidth } = useResizeObserver(rowRef);
  const [fixedWidth, setFixedWidth] = useState(0);
  const [foldableWidth, setFoldableWidth] = useState(0);
  const [folded, setFolded] = useState(false);
  const [wideWidths, setWideWidths] = useState<Record<string, number>>({});

  // A wide control can grow without the toolbar rendering again (a chip added to a combobox).
  // Each wide control is observed: a size change renders the toolbar, and the layout effect measures again.
  const [, setResized] = useState(0);
  const wideObserver = useMemo(
    () => (typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(() => setResized((count) => count + 1))),
    [],
  );
  useEffect(() => () => wideObserver?.disconnect(), [wideObserver]);
  const observeWide = useCallback((element: HTMLDivElement | null) => {
    if (!element || !wideObserver) return undefined;
    wideObserver.observe(element);
    return () => wideObserver.unobserve(element);
  }, [wideObserver]);

  const available = rowWidth > 0 ? rowWidth - padding - fixedWidth : Infinity;
  const foldNow = hasFoldable && shouldFoldCreationTools(available, foldableWidth, folded);

  // No dependency list on purpose: the widths can change on any render.
  // Each setter runs only when a width moved by more than 1 px, so the effect settles.
  useLayoutEffect(() => {
    const row = rowRef.current;
    if (!row) return;
    const widthOf = (selector: string) => Array.from(row.querySelectorAll<HTMLElement>(selector))
      .reduce((sum, element) => sum + element.offsetWidth + TOOLBAR_GAP_PX, 0);

    const fixed = widthOf(PINNED_SELECTOR);
    if (Math.abs(fixed - fixedWidth) > 1) setFixedWidth(fixed);

    // Creation tools are measured only while unfolded. Once folded, their last width decides when they unfold.
    const foldable = widthOf(CREATION_SELECTOR);
    if (!folded && Math.abs(foldable - foldableWidth) > 1) setFoldableWidth(foldable);

    if (foldNow !== folded) {
      setFolded(foldNow);
      onFoldChange?.(foldNow);
    }

    const changed: Record<string, number> = {};
    row.querySelectorAll<HTMLElement>(WIDE_CONTROL_SELECTOR).forEach((element) => {
      const id = element.getAttribute(WIDE_CONTROL_ID_ATTRIBUTE) ?? '';
      const width = element.offsetWidth + TOOLBAR_GAP_PX;
      if (Math.abs(width - (wideWidths[id] ?? -Infinity)) > 1) changed[id] = width;
    });
    if (Object.keys(changed).length > 0) setWideWidths((current) => ({ ...current, ...changed }));
  });

  let foldRoom = 0;
  if (hasFoldable) foldRoom = folded ? FOLDED_CREATION_WIDTH : foldableWidth;

  return { room: available - foldRoom, folded, wideWidths, observeWide };
};

export default useToolbarRoom;
