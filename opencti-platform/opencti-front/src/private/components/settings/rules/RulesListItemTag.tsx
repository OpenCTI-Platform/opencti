import React, { CSSProperties, PropsWithChildren } from 'react';
import { useTheme } from '@mui/material/styles';
import Tooltip from '@mui/material/Tooltip';
import type { Theme } from '../../../../components/Theme';

interface RulesListItemTagProps extends PropsWithChildren {
  variant?: 'if' | 'then' | 'action'
  color?: string | null
}

const RulesListItemTag = ({ variant, color, children }: RulesListItemTagProps) => {
  const theme = useTheme<Theme>();

  const style: CSSProperties = {
    height: 30,
    padding: 3,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    textAlign: 'center',
    border: color ? `1px solid ${color}` : 'transparent',
    flex: '1',
  };

  if (variant) {
    style.flex = '0 0 auto';
  }

  if (variant === 'if' || variant === 'then') {
    style.border = `1px solid ${theme.palette.primary.main}`;
  } else if (variant === 'action') {
    style.border = `1px solid ${theme.palette.secondary.main}`;
  }

  if (variant === 'if') {
    style.width = 30;
  } else if (variant === 'action' || variant === 'then') {
    style.width = 80;
  }

  if (variant === 'if' || variant === 'action') {
    style.marginRight = theme.spacing(3);
  }

  return (
    <Tooltip title={children}>
      <div style={style}>{children}</div>
    </Tooltip>
  );
};

export default RulesListItemTag;
