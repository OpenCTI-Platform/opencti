import { CSSProperties, ReactNode } from 'react';
import { Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../../Theme';

interface CardLabelProps {
  children: ReactNode,
  action?: ReactNode,
  style?: CSSProperties,
}

const CardTitle = ({
  children,
  action,
  style = {},
}: CardLabelProps) => {
  const theme = useTheme<Theme>();

  const containerStyle: CSSProperties = {
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'center',
    height: '19px',
    justifyContent: 'space-between',
    marginBottom: theme.spacing(1),
    ...style,
  };

  const titleStyle: CSSProperties = {
    marginBottom: 0,
    textTransform: 'capitalize',
    color: theme.palette.text.light,
    lineHeight: '19px'
  };

  return (
    <div style={containerStyle}>
      <Typography variant="body2" style={titleStyle}>
        {children}
      </Typography>
      {action}
    </div>
  );
};

export default CardTitle;
