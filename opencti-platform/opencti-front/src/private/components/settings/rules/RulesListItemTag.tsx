import React, { CSSProperties, PropsWithChildren } from 'react';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../components/Theme';
import Tag from '@common/tag/Tag';

interface RuleTagProps extends PropsWithChildren {
  action?: boolean;
  color?: string | null;
  label?: string | number | null;
}

export const RuleTag = ({ action = false, color, label }: RuleTagProps) => {
  const theme = useTheme<Theme>();

  const style: CSSProperties = {
    flex: 1,
    width: '100%',
    borderRadius: 4,
  };

  if (action) {
    style.flex = '0 0 auto';
    style.width = 80;
    style.marginRight = theme.spacing(3);
    style.paddingLeft = '4px';
  }

  const tagColor = action ? theme.palette.secondary.main : color;

  return (
    <Tag style={style} color={tagColor} label={label} labelTextTransform={action ? 'uppercase' : undefined} />
  );
};
