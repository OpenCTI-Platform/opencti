import { PropsWithChildren, ReactNode } from 'react';
import { useTheme } from '@mui/styles';
import { Stack, SxProps, Card as CardMui } from '@mui/material';
import CardTitle from './CardTitle';
import { Theme } from '../../Theme';

interface CardProps extends PropsWithChildren {
  title?: ReactNode;
  action?: ReactNode;
  noPadding?: boolean;
  sx?: SxProps;
  titleSx?: SxProps;
  fullHeight?: boolean;
  onClick?: () => void;
}

const Card = ({
  title,
  children,
  action,
  noPadding = false,
  sx = {},
  titleSx,
  fullHeight = true,
  onClick,
}: CardProps) => {
  const theme = useTheme<Theme>();

  const containerSx: SxProps = {
    position: 'relative',
    flexGrow: fullHeight ? 1 : 0,
    padding: noPadding ? 0 : theme.spacing(3),
    borderRadius: theme.spacing(0.5),
    background: theme.palette.background.secondary,
    ...sx,
  };

  return (
    <Stack sx={{ height: '100%' }}>
      {title && (
        <CardTitle action={action} sx={titleSx}>
          {title}
        </CardTitle>
      )}
      <CardMui sx={containerSx} onClick={onClick}>
        {children}
      </CardMui>
    </Stack>
  );
};

export default Card;
