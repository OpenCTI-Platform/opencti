import Chip from '@mui/material/Chip';
import { useTheme } from '@mui/styles';
import React from 'react';
import ItemStatus from '../../../../components/ItemStatus';
import type { Theme } from '../../../../components/Theme';
import { hexToRGB } from '../../../../utils/Colors';
import { getDraftModeColor } from './DraftChip';

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
  const theme = useTheme<Theme>();
  const draftColor = getDraftModeColor(theme);
  const validatedDraftColor = theme.palette.success.main;

  if (workflowCurrentStatus) {
    return <ItemStatus status={workflowCurrentStatus} />;
  }

  const color = draftStatus === 'open' ? draftColor : validatedDraftColor;

  return (
    <Chip
      variant="outlined"
      label={draftStatus}
      style={{
        fontSize: 12,
        lineHeight: '12px',
        height: 20,
        float: 'left',
        textTransform: 'uppercase',
        borderRadius: 4,
        width: 90,
        color,
        borderColor: color,
        backgroundColor: hexToRGB(color),
      }}
    />
  );
};

export default DraftStatusChip;
