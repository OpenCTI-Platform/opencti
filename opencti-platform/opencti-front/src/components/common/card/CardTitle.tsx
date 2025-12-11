import { CSSProperties, PropsWithChildren, ReactNode } from 'react';
import { Stack, SxProps, Typography } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../../Theme';

interface CardTitleProps extends PropsWithChildren {
  action?: ReactNode,
  style?: CSSProperties,
}

const CardTitle = ({
  children,
  action,
  style = {},
}: CardTitleProps) => {
  const theme = useTheme<Theme>();

  const containerSx: SxProps = {
    height: '19px',
    marginBottom: theme.spacing(1),
    ...style,
  };

  const titleSx: SxProps = {
    marginBottom: 0,
    textTransform: 'capitalize',
    color: theme.palette.text.light,
    lineHeight: '19px'
  };

  return (
    <Stack 
      direction='row'
      justifyContent='space-between'
      alignItems='end'
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
