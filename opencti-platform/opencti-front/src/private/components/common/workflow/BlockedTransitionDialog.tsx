import React, { FunctionComponent, RefObject, Suspense, useMemo } from 'react';
import { PreloadedQuery } from 'react-relay';
import { Button, Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogTitle, Text } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { useEntityEditionOpener } from '../../../../components/entityEditionOpener';
import FilterValues from '../../../../components/filters/FilterValues';
import FilterKeyLabel from '../../../../components/filters/FilterKeyLabel';
import useFilterRepresentatives from '../../../../components/filters/useFilterRepresentatives';
import { filterValuesContentQuery } from '../../../../components/FilterValuesContent';
import type { FilterValuesContentQuery } from '../../../../components/__generated__/FilterValuesContentQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import type { Filter, FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { parseBlockingConditions } from './blockedTransitionConditions';

type ConditionRow = { id: string; mode: string; filters: Filter[] };

const flattenFilters = (group: FilterGroup): Filter[] => [
  ...(group.filters ?? []),
  ...(group.filterGroups ?? []).flatMap(flattenFilters),
];

// One row per top-level condition, and one row per nested group (its
// conditions joined by the group's own mode).
const toRows = (filters: FilterGroup): ConditionRow[] => [
  ...(filters.filters ?? []).map((f, i) => ({ id: `filter-${i}`, mode: filters.mode, filters: [f] })),
  ...(filters.filterGroups ?? []).map((g, i) => ({ id: `group-${i}`, mode: g.mode, filters: flattenFilters(g) })),
];

interface ConditionRowsProps {
  filters: FilterGroup;
  entityType: string;
  queryRef: PreloadedQuery<FilterValuesContentQuery>;
}

const ConditionRows: FunctionComponent<ConditionRowsProps> = ({ filters, entityType, queryRef }) => {
  const { t_i18n } = useFormatter();
  const entityTypes = useMemo(() => [entityType], [entityType]);
  const { filtersRepresentativesMap, filterKeysMap } = useFilterRepresentatives({
    filtersRepresentativesQueryRef: queryRef,
    entityTypes,
  });
  const modeLabel = (mode: string) => t_i18n((mode ?? 'and').toUpperCase());
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {toRows(filters).map((row, rowIndex) => (
        <React.Fragment key={row.id}>
          {rowIndex > 0 && (
            <Text as="span" variant="content-compact" className="text-default-secondary">
              {modeLabel(filters.mode)}
            </Text>
          )}
          <div
            data-testid="workflow-blocked-dialog-condition"
            style={{ overflowWrap: 'anywhere', whiteSpace: 'normal' }}
          >
            {row.filters.map((filter, filterIndex) => (
              <span key={`${row.id}-${filter.key}-${filter.values.join(',')}`}>
                {filterIndex > 0 && ` ${modeLabel(row.mode)} `}
                <FilterValues
                  label={<FilterKeyLabel filter={filter} filterKeysMap={filterKeysMap} />}
                  tooltip
                  currentFilter={filter}
                  filtersRepresentativesMap={filtersRepresentativesMap}
                  entityTypes={entityTypes}
                />
              </span>
            ))}
          </div>
        </React.Fragment>
      ))}
    </div>
  );
};

const BlockingConditions: FunctionComponent<{ filters: FilterGroup; entityType: string }> = ({ filters, entityType }) => {
  const queryRef = useQueryLoading<FilterValuesContentQuery>(filterValuesContentQuery, {
    filters: normalizeFilterGroupForBackend(filters),
    // Conditions such as "assignee is @me" are legitimate here.
    isMeValueForbidden: false,
  });
  if (!queryRef) return null;
  return (
    <Suspense fallback={<span />}>
      <ConditionRows filters={filters} entityType={entityType} queryRef={queryRef} />
    </Suspense>
  );
};

interface BlockedTransitionDialogProps {
  open: boolean;
  onClose: () => void;
  event: string;
  entityType: string;
  toStatusName: string | undefined;
  blockingConditions: string | null | undefined;
  // The dialog has no trigger of its own (it opens from a menu item), so Radix
  // cannot restore focus on close: this element gets it back instead.
  returnFocusTo?: RefObject<HTMLElement | null>;
}

const BlockedTransitionDialog: FunctionComponent<BlockedTransitionDialogProps> = ({
  open,
  onClose,
  event,
  entityType,
  toStatusName,
  blockingConditions,
  returnFocusTo,
}) => {
  const { t_i18n } = useFormatter();
  const openEdition = useEntityEditionOpener();
  const filters = useMemo(() => parseBlockingConditions(blockingConditions), [blockingConditions]);
  const entityLabel = t_i18n(`entity_${entityType}`);
  const handleEdit = () => {
    onClose();
    openEdition?.();
  };
  return (
    <Dialog
      open={open}
      onOpenChange={(isOpen) => {
        if (!isOpen) onClose();
      }}
    >
      <DialogContent
        size="sm"
        data-testid="workflow-blocked-dialog"
        onCloseAutoFocus={(e) => {
          if (!returnFocusTo?.current) return;
          e.preventDefault();
          returnFocusTo.current.focus();
        }}
      >
        <DialogTitle>{t_i18n('“{event}” is not available yet', { values: { event } })}</DialogTitle>
        <DialogDescription>
          {t_i18n('Meet every condition below to move this {entityType} to {status}.', {
            values: { entityType: entityLabel, status: toStatusName ?? '' },
          })}
        </DialogDescription>
        <DialogBody>
          {open && filters && <BlockingConditions filters={filters} entityType={entityType} />}
        </DialogBody>
        <DialogFooter>
          <Button priority="secondary" onClick={onClose} data-testid="workflow-blocked-dialog-dismiss">
            {t_i18n('Dismiss')}
          </Button>
          {openEdition && (
            <Button priority="primary" onClick={handleEdit} data-testid="workflow-blocked-dialog-edit">
              {t_i18n('Edit {entityType}', { values: { entityType: entityLabel } })}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default BlockedTransitionDialog;
