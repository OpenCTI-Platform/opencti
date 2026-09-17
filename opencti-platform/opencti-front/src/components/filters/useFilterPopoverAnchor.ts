import React, { useEffect, useRef, useState } from 'react';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import { FilterChipsParameter } from './FilterChipPopover';

interface UseFilterPopoverAnchorArgs {
  helpers?: handleFilterHelpers;
  displayedFilters: Filter[];
  hasRenderedRef: boolean;
  setHasRenderedRef: (value: boolean) => void;
  setFilterChipsParams: React.Dispatch<React.SetStateAction<FilterChipsParameter>>;
}

const getAnchorPosition = (element: HTMLElement) => {
  const rect = element.getBoundingClientRect();
  return { top: rect.bottom, left: rect.left };
};

/**
 * Owns every anchoring concern of the filter chip line: which chip the value popover hangs
 * on, which nested group panel is open, and the click-away gesture that closes that panel.
 *
 * Kept out of the rendering components so the positioning rules can evolve (and be tested)
 * without touching the chips themselves.
 */
const useFilterPopoverAnchor = ({
  helpers,
  displayedFilters,
  hasRenderedRef,
  setHasRenderedRef,
  setFilterChipsParams,
}: UseFilterPopoverAnchorArgs) => {
  const itemRefToPopover = useRef(null);
  const oldItemRefToPopover = useRef(null);
  const filterLineRef = useRef<HTMLDivElement | null>(null);
  const chipRefs = useRef<Record<string, HTMLSpanElement | null>>({});
  const [openedGroupId, setOpenedGroupId] = useState<string | undefined>(undefined);

  // activate popover feature on chip only when "helper" is defined, not the best way to handle but
  // it means that the new filter feature is activated. Will be removed in the next version when we generalize the feature on every filter.
  useEffect(() => {
    if (!helpers) return;
    const latestFilterId = helpers.getLatestAddFilterId();
    const newFilterAdded = hasRenderedRef
      && latestFilterId
      && itemRefToPopover.current
      && oldItemRefToPopover.current !== itemRefToPopover.current;
    if (newFilterAdded) {
      const anchorEl = itemRefToPopover.current as unknown as HTMLElement;
      const anchorPosition = getAnchorPosition(anchorEl);
      setFilterChipsParams({
        filterId: latestFilterId,
        anchorEl,
        anchorPosition,
      });
    } else {
      setHasRenderedRef(true);
    }
    oldItemRefToPopover.current = itemRefToPopover.current;
  }, [displayedFilters, helpers, hasRenderedRef, setFilterChipsParams, setHasRenderedRef]);

  const handleClose = () => {
    setFilterChipsParams({
      filterId: undefined,
      anchorEl: undefined,
      anchorPosition: undefined,
    });
  };

  const handleChipClick = (
    event: React.MouseEvent<HTMLButtonElement>,
    filterId?: string,
  ) => {
    if (helpers) {
      const anchorEl = event.currentTarget.parentElement ?? event.currentTarget;
      const anchorPosition = getAnchorPosition(anchorEl);
      setFilterChipsParams({
        filterId,
        anchorEl,
        anchorPosition,
      });
    }
  };

  const registerChipRef = (groupId: string, node: HTMLSpanElement | null) => {
    chipRefs.current[groupId] = node;
  };

  const toggleGroup = (groupId?: string) => {
    setOpenedGroupId((current) => (current === groupId ? undefined : groupId));
  };

  const handleClickAwayPanel = (event: MouseEvent | TouchEvent) => {
    // This listener runs on `pointerdown` (see `mouseEvent` on the ClickAwayListener in the panel
    // host), so the chip that toggles the panel would be closed here and immediately reopened by
    // its own click handler. The chip owns its toggle: ignore the gesture when it starts inside it.
    const target = event.target as Node | null;
    if (openedGroupId && target && chipRefs.current[openedGroupId]?.contains(target)) {
      return;
    }
    setOpenedGroupId(undefined);
  };

  return {
    /** Ref put on the chip of the freshly added filter, anchor of the value popover. */
    itemRefToPopover,
    /** Ref on the chip line, anchor of the nested group panel. */
    filterLineRef,
    openedGroupId,
    toggleGroup,
    registerChipRef,
    handleChipClick,
    handleClose,
    handleClickAwayPanel,
  };
};

export default useFilterPopoverAnchor;
