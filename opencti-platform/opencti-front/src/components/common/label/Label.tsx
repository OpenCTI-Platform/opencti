import { PropsWithChildren, ReactNode } from 'react';
import { Stack, SxProps, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../../Theme';

interface LabelProps extends PropsWithChildren {
  action?: ReactNode;
}

const Label = ({
  children,
  action,
}: LabelProps) => {
  const theme = useTheme<Theme>();

  const containerSx: SxProps = {
    height: '19px',
    marginBottom: theme.spacing(0.5),
  };

  const titleSx: SxProps = {
    marginBottom: 0,
    textTransform: 'capitalize',
    color: theme.palette.text.light,
    lineHeight: '19px',
  };

  return (
    <Stack
      direction="row"
      alignItems="center"
      sx={containerSx}
      gap={0.5}
    >
      <Typography variant="body2" sx={titleSx}>
        {children}
      </Typography>
      {action}
    </Stack>
  );
};

export default Label;
