import { PropsWithChildren, ReactNode } from 'react';
import { Stack, StackProps, SxProps, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../../Theme';

interface CardTitleProps extends PropsWithChildren {
  action?: ReactNode;
  alignItems?: StackProps['alignItems'];
  sx?: SxProps;
}

const CardTitle = ({
  children,
  alignItems = 'center',
  action,
  sx = {},
}: CardTitleProps) => {
  const theme = useTheme<Theme>();

  const containerSx: SxProps = {
    height: alignItems !== 'center' ? 'inherit' : '19px',
    marginBottom: theme.spacing(1),
    flex: 0,
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
      alignItems={alignItems}
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
