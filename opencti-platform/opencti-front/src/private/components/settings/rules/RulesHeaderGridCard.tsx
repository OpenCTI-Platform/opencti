import React, { CSSProperties, PropsWithChildren, ReactNode } from 'react';
import { Card, CardContent } from '@mui/material';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../components/Theme';

interface RulesHeaderGridCardProps extends PropsWithChildren {
  title: string
  icon: ReactNode
}

const RulesHeaderGridCard = ({
  title,
  children,
  icon,
}: RulesHeaderGridCardProps) => {
  const theme = useTheme<Theme>();

  const styleCard: CSSProperties = {
    position: 'relative',
    height: 114,
    display: 'flex',
    alignItems: 'center',
  };
  const styleTitle: CSSProperties = {
    textTransform: 'uppercase',
    fontSize: 12,
    fontWeight: 500,
    color: theme.palette.text?.secondary,
  };
  const styleIcon: CSSProperties = {
    position: 'absolute',
    color: theme.palette.primary.main,
    top: 35,
    right: 20,
  };

  return (
    <Card style={styleCard} variant="outlined">
      <CardContent sx={{ '&:last-child': { padding: 2 } }}>
        <Typography style={styleTitle}>{title}</Typography>
        {children}
        <div style={styleIcon}>{icon}</div>
      </CardContent>
    </Card>
  );
};

export default RulesHeaderGridCard;
