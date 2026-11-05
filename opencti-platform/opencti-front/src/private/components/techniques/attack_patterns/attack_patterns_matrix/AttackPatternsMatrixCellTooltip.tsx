import React, { ReactElement } from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import { formatNameList } from '../../../workspaces/investigations/matrix/investigationMatrixUtils';
import type { CellDecoration } from '../../../workspaces/investigations/matrix/matrixTypes';

const MAX_LISTED_ENTITIES = 10;

interface AttackPatternsMatrixCellTooltipProps {
  decoration?: CellDecoration;
  // A single element that forwards its ref and props: it is the tooltip trigger, so hover and focus both open it.
  children: ReactElement;
}

// Lists the entities linked to a cell. Without linked entities the cell renders as is.
const AttackPatternsMatrixCellTooltip = ({ decoration, children }: AttackPatternsMatrixCellTooltipProps) => {
  const { t_i18n } = useFormatter();
  const linkedEntities = decoration?.linkedEntities ?? [];
  if (linkedEntities.length === 0) return children;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent>
        <strong>{t_i18n('Linked entities ({count})', { values: { count: linkedEntities.length } })}</strong>
        <br />
        {formatNameList(linkedEntities.map(({ name }) => name), MAX_LISTED_ENTITIES, t_i18n)}
      </TooltipContent>
    </Tooltip>
  );
};

export default AttackPatternsMatrixCellTooltip;
