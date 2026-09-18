import Box from '@mui/material/Box';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import { Stack } from '@mui/material';
import { Theme, useTheme } from '@mui/material/styles';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import React, { CSSProperties, Fragment, FunctionComponent, PropsWithChildren, Ref, useContext } from 'react';
import {
  convertOperatorToIcon,
  FILTER_LINE_ITEM_HEIGHT,
  filterOperatorsWithIcon,
  FiltersRestrictions,
  getFilterDefinitionFromFilterKeysMap,
  isFilterEditable,
  NO_VALUES_FILTER_OPERATORS,
} from '../../utils/filters/filtersUtils';
import { truncate } from '../../utils/String';
import type { WidgetHost } from '../../utils/widget/widget';
import { Filter, FilterGroup, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import { FilterIconButtonVariant } from '../FilterIconButtonContainer';
import FilterIconButtonGlobalMode from '../FilterIconButtonGlobalMode';
import { PageContainerContext } from '../PageContainer';
import { useFormatter } from '../i18n';
import FilterValues from './FilterValues';
import FilterChip from './FilterChip';
import { FilterRepresentative } from './FiltersModel';
import FilterGroupChipButton from './group/FilterGroupChipButton';
import { FilterDefinition } from '../../utils/hooks/useAuth';

/** Geometry of a filter chip and of its operator badge, per display variant. */
const getChipStyles = (theme: Theme, variant?: FilterIconButtonVariant) => {
  const operatorStyle: CSSProperties = {
    borderRadius: 4,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    padding: '0 8px',
    display: 'flex',
    alignItems: 'center',
  };
  if (variant === 'small') {
    return {
      filterStyle: {
        fontSize: 12,
        height: 20,
        borderRadius: 4,
        lineHeight: `${FILTER_LINE_ITEM_HEIGHT}px`,
      } as CSSProperties,
      operatorStyle: {
        borderRadius: 4,
        fontFamily: 'Consolas, monaco, monospace',
        backgroundColor: theme.palette.action?.selected,
        padding: '0 8px',
        height: 20,
        marginRight: 5,
        marginLeft: 5,
      } as CSSProperties,
    };
  }
  if (variant === 'tag') {
    return { filterStyle: { height: 25 } as CSSProperties, operatorStyle };
  }
  return { filterStyle: undefined as CSSProperties | undefined, operatorStyle };
};

/**
 * Geometry of the line itself. A read-only line (no helpers, no remove handler) is rendered
 * inside another layout — e.g. an entity overview — so it claims no margin and no wrapping.
 */
const getLineStyle = ({
  variant,
  isReadWriteFilter,
  inPageContainer,
  hasSavedFilters,
}: {
  variant?: FilterIconButtonVariant;
  isReadWriteFilter: boolean;
  inPageContainer: boolean;
  hasSavedFilters?: boolean;
}) => {
  if (!isReadWriteFilter) {
    return {
      margin: '0 0 0 0',
      display: 'flex',
      flexWrap: 'no-wrap',
      gap: 0,
      overflow: 'hidden',
      backgroundColor: 'none',
      borderRadius: '0px',
    };
  }
  const margin = (inPageContainer || variant === 'small') ? '0 0 0 0' : '0 0 8px 0';
  return {
    margin,
    display: 'flex',
    flexWrap: 'wrap',
    gap: 1,
    overflow: 'hidden',
    backgroundColor: hasSavedFilters ? 'rgba(37, 150, 190, 0.3)' : 'transparent',
    borderRadius: hasSavedFilters ? '4px' : '0px',
  };
};

export interface FilterChipLineProps {
  displayedFilters: Filter[];
  displayedFilterGroups: FilterGroup[];
  globalMode: string;
  filterKeysMap: Map<string, FilterDefinition>;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  variant?: FilterIconButtonVariant;
  chipColor?: ChipOwnProps['color'];
  disabledPossible?: boolean;
  redirection?: boolean;
  filtersRestrictions?: FiltersRestrictions;
  entityTypes?: string[];
  host?: WidgetHost;
  hasSavedFilters?: boolean;
  helpers?: handleFilterHelpers;
  handleRemoveFilter?: (key: string, op?: string) => void;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  /** Group whose nested panel is currently open, highlighted in the line. */
  openedGroupId?: string;
  onToggleGroup: (groupId?: string) => void;
  registerChipRef: (groupId: string, node: HTMLSpanElement | null) => void;
  onChipClick: (event: React.MouseEvent<HTMLButtonElement>, filterId?: string) => void;
  /** Anchor of the value popover, set on the chip of the last added filter. */
  latestFilterChipRef: Ref<HTMLDivElement>;
  lineRef: Ref<HTMLDivElement>;
}

/**
 * Renders the horizontal line of filter chips: one chip per nested filter group, one per
 * filter, separated by the global mode (AND/OR) switch.
 *
 * Pure rendering: anchoring and open/close state live in `useFilterPopoverAnchor`, so this
 * component can be reasoned about (and snapshot) without any positioning concern. Children
 * are rendered at the end of the line, which is where the value popover anchors.
 */
const FilterChipLine: FunctionComponent<PropsWithChildren<FilterChipLineProps>> = ({
  displayedFilters,
  displayedFilterGroups,
  globalMode,
  filterKeysMap,
  filtersRepresentativesMap,
  variant,
  chipColor,
  disabledPossible,
  redirection,
  filtersRestrictions,
  entityTypes,
  host,
  hasSavedFilters,
  helpers,
  handleRemoveFilter,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  openedGroupId,
  onToggleGroup,
  registerChipRef,
  onChipClick,
  latestFilterChipRef,
  lineRef,
  children,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { inPageContainer } = useContext(PageContainerContext);

  const isReadWriteFilter = !!(helpers || handleRemoveFilter);
  const { filterStyle, operatorStyle } = getChipStyles(theme, variant);
  const lineStyle = getLineStyle({ variant, isReadWriteFilter, inPageContainer, hasSavedFilters });

  const manageRemoveFilter = (
    currentFilterId: string | undefined,
    filterKey: string,
    filterOperator: string,
  ) => {
    if (helpers && currentFilterId) {
      helpers?.handleRemoveFilterById(currentFilterId);
    } else if (handleRemoveFilter) {
      handleRemoveFilter(filterKey, filterOperator ?? undefined);
    }
  };

  const globalModeSeparator = (
    <Box
      sx={{
        padding: variant === 'small' ? '0 4px' : '0',
        display: 'flex',
      }}
    >
      <FilterIconButtonGlobalMode
        operatorStyle={operatorStyle}
        isOperatorClickable={isReadWriteFilter}
        globalMode={globalMode}
        handleSwitchGlobalMode={() => {
          if (helpers?.handleSwitchGlobalMode) {
            helpers.handleSwitchGlobalMode();
          } else if (handleSwitchGlobalMode) {
            handleSwitchGlobalMode();
          }
        }}
      />
    </Box>
  );

  return (
    <Box sx={lineStyle} ref={lineRef}>
      {displayedFilterGroups.map((group, index) => (
        <Fragment key={group.id ?? `filter-group-${index}`}>
          <FilterGroupChipButton
            ref={(node) => {
              registerChipRef(group.id ?? '', node);
            }}
            filterGroup={group}
            isOpen={openedGroupId === group.id}
            chipColor={chipColor}
            style={filterStyle}
            onClick={() => onToggleGroup(group.id)}
          />
          {(index < displayedFilterGroups.length - 1 || displayedFilters.length > 0) && globalModeSeparator}
        </Fragment>
      ))}
      {displayedFilters.map((currentFilter, index) => {
        const filterKey = currentFilter.key;
        const filterLabel = t_i18n(getFilterDefinitionFromFilterKeysMap(filterKey, filterKeysMap)?.label ?? filterKey);
        const filterOperator = currentFilter.operator ?? 'eq';
        const filterValues = currentFilter.values;
        const isOperatorDisplayed = filterOperatorsWithIcon.includes(filterOperator ?? 'eq');
        const keyLabel = (
          <>
            {truncate(filterLabel, 20)}
            {!isOperatorDisplayed && (
              <Box
                component="span"
                sx={{ padding: '0 4px', fontWeight: 'normal' }}
              >
                {t_i18n(filterOperator)}
              </Box>
            )}
            {isOperatorDisplayed
              ? convertOperatorToIcon(filterOperator ?? 'eq')
              : currentFilter.values.length > 0 && ':'}
          </>
        );
        const isNotLastFilter = index < displayedFilters.length - 1;

        const chipVariant = currentFilter.values.length === 0 && !NO_VALUES_FILTER_OPERATORS.includes(filterOperator ?? 'eq')
          ? 'outlined'
          : 'filled';
        // darken the bg color when filled (quickfix for 'warning' and 'success' chipColor unreadable with regardingOf filter)
        const darkenChipBackground = (chipColor === 'warning' || chipColor === 'success') && chipVariant === 'filled';
        const authorizeFilterRemoving = !(filtersRestrictions?.preventRemoveFor?.includes(filterKey))
          && isFilterEditable(filtersRestrictions, filterKey, filterValues);
        const tooltipContent = filterKey === 'regardingOf' || filterKey === 'dynamicRegardingOf'
          ? undefined
          : (
              // As inline content the key, the values and the operator sat on three different baselines.
              <Box
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '4px',
                }}
              >
                <FilterValues
                  label={keyLabel}
                  tooltip={true}
                  currentFilter={currentFilter}
                  handleSwitchLocalMode={handleSwitchLocalMode}
                  filtersRepresentativesMap={filtersRepresentativesMap}
                  redirection={redirection}
                  entityTypes={entityTypes}
                  filtersRestrictions={filtersRestrictions}
                  host={host}
                />
              </Box>
            );
        const chip = (
          <Box
            sx={{
              padding: '0',
              display: 'flex',
            }}
          >
            <FilterChip
              color={chipColor}
              ref={
                helpers?.getLatestAddFilterId() === currentFilter.id
                  ? latestFilterChipRef
                  : null
              }
              variant={chipVariant}
              darkenBackground={darkenChipBackground}
              style={filterStyle}
              disabled={disabledPossible ? displayedFilters.length === 1 : undefined}
              label={filterLabel}
              onDelete={
                (isReadWriteFilter && authorizeFilterRemoving)
                  ? () => manageRemoveFilter(
                      currentFilter.id,
                      filterKey,
                      filterOperator,
                    )
                  : undefined
              }
            >
              <Stack
                alignItems="center"
                direction="row"
                gap={0.5}
                sx={{
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                <FilterValues
                  label={keyLabel}
                  tooltip={false}
                  currentFilter={currentFilter}
                  handleSwitchLocalMode={helpers?.handleSwitchLocalMode ?? handleSwitchLocalMode}
                  filtersRepresentativesMap={filtersRepresentativesMap}
                  redirection={redirection}
                  onClickLabel={(event) => onChipClick(event, currentFilter?.id)}
                  isReadWriteFilter={isReadWriteFilter}
                  chipColor={chipColor}
                  entityTypes={entityTypes}
                  filtersRestrictions={filtersRestrictions}
                  host={host}
                />
              </Stack>
            </FilterChip>
          </Box>
        );
        return (
          <Fragment key={currentFilter.id ?? `filter-${index}`}>
            {tooltipContent
              ? (
                  <Tooltip>
                    <TooltipTrigger asChild>{chip}</TooltipTrigger>
                    <TooltipContent>{tooltipContent}</TooltipContent>
                  </Tooltip>
                )
              : chip}
            {isNotLastFilter && globalModeSeparator}
          </Fragment>
        );
      })}
      {children}
    </Box>
  );
};

export default FilterChipLine;
