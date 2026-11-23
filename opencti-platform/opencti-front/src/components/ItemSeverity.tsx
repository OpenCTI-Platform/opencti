import React, { FunctionComponent } from 'react';
import { SxProps } from '@mui/material/styles';
import Tag from '@common/tag/Tag';
import { EMPTY_VALUE } from '../utils/String';
import { severityTone } from '../utils/severityTone';

interface ItemSeverityProps {
  label?: string | null;
  severity?: string | null;
  variant?: 'inList' | 'high';
}

const ItemSeverity: FunctionComponent<ItemSeverityProps> = ({
  label,
  severity,
}) => {
  if (!severity) {
    return <>{EMPTY_VALUE}</>;
  }

  const sxStyle: SxProps = {
    textTransform: 'lowercase',
    '& :first-letter': {
      textTransform: 'uppercase',
    },
  };

  return <Tag label={label} severity={severityTone(severity)} sx={sxStyle} />;
};
export default ItemSeverity;
