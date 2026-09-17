import Box from '@mui/material/Box';
import { ClickAwayListener, Grow, Popper } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Paper } from '@filigran/design-system';
import { FunctionComponent, ReactNode, RefObject } from 'react';
import type { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import { FilterEditorContextValue, FilterEditorProvider } from '../fields/FilterEditorContext';
import FilterGroupPanel from './FilterGroupPanel';

// Stable identity: a fresh `new Map()` default would defeat the provider's memoization.
const EMPTY_REPRESENTATIVES_MAP: FilterEditorContextValue['filtersRepresentativesMap'] = new Map();

interface FilterGroupPanelHostProps extends Omit<FilterEditorContextValue, 'filtersRepresentativesMap'> {
  /** Group being edited, `undefined` closes the host. */
  group?: FilterGroup;
  filtersRepresentativesMap?: FilterEditorContextValue['filtersRepresentativesMap'];
  /**
   * When true, the panel is rendered in the normal document flow (a plain Box) instead of a
   * floating `Popper`. Used in contexts where a floating panel would overflow its container
   * without resizing it, e.g. the widget creation dialog.
   */
  inline?: boolean;
  /** Element the floating panel is sized and positioned against (the chip line). */
  anchorRef: RefObject<HTMLDivElement | null>;
  onClickAway: (event: MouseEvent | TouchEvent) => void;
}

/**
 * Presents the nested filter group editor, either inline or floating.
 *
 * The two presentations share the same panel and the same padding, so they are kept in one
 * place: adding a third presentation, or changing the panel props, is a single edit here.
 *
 * Also the root of the editor context for this tree: the panel and everything below it read the
 * tree-wide editor configuration from it instead of forwarding it prop by prop. The defaults the
 * panel used to apply itself are applied here, where the context is built.
 */
const FilterGroupPanelHost: FunctionComponent<FilterGroupPanelHostProps> = ({
  group,
  inline,
  anchorRef,
  onClickAway,
  helpers,
  availableFilterKeys,
  entityTypes = ['Stix-Core-Object'],
  filtersRepresentativesMap = EMPTY_REPRESENTATIVES_MAP,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  searchContext,
  host,
}) => {
  const theme = useTheme();

  const panel: ReactNode = group && (
    <Box sx={{ padding: 2 }}>
      <FilterGroupPanel group={group} />
    </Box>
  );

  const withContext = (children: ReactNode) => (
    <FilterEditorProvider
      helpers={helpers}
      availableFilterKeys={availableFilterKeys}
      entityTypes={entityTypes}
      filtersRepresentativesMap={filtersRepresentativesMap}
      availableEntityTypes={availableEntityTypes}
      availableRelationshipTypes={availableRelationshipTypes}
      availableRelationFilterTypes={availableRelationFilterTypes}
      searchContext={searchContext}
      host={host}
    >
      {children}
    </FilterEditorProvider>
  );

  if (inline) {
    if (!group) return null;
    return (
      <Box sx={{ width: '100%', marginTop: 1 }}>
        <Paper padding={0} style={{ width: '100%' }}>
          {withContext(panel)}
        </Paper>
      </Box>
    );
  }

  return (
    <Popper
      open={Boolean(group)}
      anchorEl={anchorRef.current}
      placement="bottom-start"
      disablePortal
      transition
      // Sized against the wrapping `Box` (position: relative) instead of a JS-measured
      // offsetWidth: stays in sync with the chip line's real width on every resize /
      // sidebar collapse, with no state tracking needed.
      style={{ width: '100%', zIndex: theme.zIndex.modal }}
    >
      {({ TransitionProps }) => (
        <Grow {...TransitionProps} style={{ transformOrigin: 'left top' }}>
          <Paper padding={0} style={{ width: '100%', marginTop: 8 }}>
            {/* The decision must be taken on `pointerdown`: the design system Select opens on
                that event and portals its content, and the resulting `click` is then dispatched
                on the common ancestor of the trigger and of the freshly mounted content, i.e.
                the document element — outside the panel and outside any React tree, where no
                listener can recognize it. On `pointerdown` the target is still the trigger.
                Clicks landing inside an already open portal are handled by ClickAwayListener
                itself, which forgives events bubbling through a React portal.
                FDS-WORKAROUND #61: removable once SelectContent accepts `portalled`. */}
            <ClickAwayListener mouseEvent="onPointerDown" onClickAway={onClickAway}>
              <Box sx={{ padding: 2 }}>
                {group && withContext(<FilterGroupPanel group={group} />)}
              </Box>
            </ClickAwayListener>
          </Paper>
        </Grow>
      )}
    </Popper>
  );
};

export default FilterGroupPanelHost;
