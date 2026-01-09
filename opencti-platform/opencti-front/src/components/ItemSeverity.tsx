import React, { FunctionComponent } from 'react';
import { SxProps, useTheme } from '@mui/material/styles';
import Tag from '@common/tag/Tag';
import type { Theme } from './Theme';

interface ItemSeverityProps {
  label: string;
  severity?: string | null;
  variant?: 'inList' | 'high';
}

const ItemSeverity: FunctionComponent<ItemSeverityProps> = ({
  label,
  severity,
}) => {
  const theme = useTheme<Theme>();

  let severityColor = theme.palette.severity.default;
  switch (severity?.toLowerCase()) {
    case 'low':
      severityColor = theme.palette.severity.low;
      break;
    case 'medium':
      severityColor = theme.palette.severity.medium;
      break;
    case 'high':
      severityColor = theme.palette.severity.high;
      break;
    case 'critical':
      severityColor = theme.palette.severity.critical;
      break;
    default:
      severityColor = theme.palette.severity.default;
      break;
  }

  const sxStyle: SxProps = {
    textTransform: 'lowercase',
    '& :first-letter': {
      textTransform: 'uppercase',
    },
  };

  return <Tag label={label} color={severityColor} sx={sxStyle} />;
};
export default ItemSeverity;
