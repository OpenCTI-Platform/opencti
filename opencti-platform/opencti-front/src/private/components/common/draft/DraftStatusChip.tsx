import { Chip } from '@filigran/design-system';
import React from 'react';
import ItemStatus from '../../../../components/ItemStatus';

interface DraftStatusChipProps {
  draftStatus: string | null | undefined;
  workflowCurrentStatus?: {
    readonly id: string;
    readonly template: {
      readonly name: string;
      readonly color: string;
    } | null | undefined;
  } | null;
}

const DraftStatusChip: React.FC<DraftStatusChipProps> = ({ draftStatus, workflowCurrentStatus }) => {
  if (workflowCurrentStatus) {
    return <ItemStatus status={workflowCurrentStatus} />;
  }

  return (
    <Chip
      // `?? ''` keeps the previous rendering: MUI accepted an undefined label
      // and drew an empty chip, the library's label is a required string.
      label={draftStatus ?? ''}
      severity={draftStatus === 'open' ? 'high' : 'low'}
      style={{ float: 'left' }}
    />
  );
};

export default DraftStatusChip;
