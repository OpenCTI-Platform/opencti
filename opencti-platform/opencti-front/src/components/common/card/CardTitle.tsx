import { PropsWithChildren, ReactNode } from 'react';
import { Stack, SxProps, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../../Theme';

interface CardTitleProps extends PropsWithChildren {
  action?: ReactNode;
  sx?: SxProps;
}

const CardTitle = ({
  children,
  action,
  sx = {},
}: CardTitleProps) => {
  const theme = useTheme<Theme>();

  const containerSx: SxProps = {
    height: '19px',
    marginBottom: theme.spacing(1),
    ...sx,
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
      justifyContent="space-between"
      alignItems="center"
      sx={containerSx}
    >
      <Typography variant="body2" sx={titleSx}>
        {children}
      </Typography>
      {action}
    </Stack>
  );
};

export default CardTitle;
