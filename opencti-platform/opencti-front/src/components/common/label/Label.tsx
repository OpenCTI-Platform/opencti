import { PropsWithChildren, ReactNode } from 'react';
import { Stack, SxProps, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../../Theme';
import { PropsWithSx } from '../../../utils/props';

interface LabelProps extends PropsWithChildren, PropsWithSx {
  action?: ReactNode;
  variant?: 'default' | 'primary';
}

const Label = ({
  children,
  action,
  sx,
  variant = 'default',
}: LabelProps) => {
  const theme = useTheme<Theme>();

  const containerSx: SxProps = {
    height: '21px',
    marginBottom: theme.spacing(0.5),
    ...sx,
  };

  const titleStyle = variant === 'default'
    ? { color: theme.palette.text.light, textTransform: 'capitalize' }
    : { color: theme.palette.text.primary, textTransform: 'none' };

  const titleSx: SxProps = {
    marginBottom: 0,
    lineHeight: '21px',
    fontSize: '12px',
    fontWeight: 400,
    fontFamily: '"IBM Plex Sans", sans-serif',
    ...titleStyle,
  };

  return (
    <Stack
      direction="row"
      alignItems="center"
      sx={containerSx}
      gap={0.5}
    >
      <Typography variant="h6" sx={titleSx}>
        {children}
      </Typography>
      {action}
    </Stack>
  );
};

export default Label;
