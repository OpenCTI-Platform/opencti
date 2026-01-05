import { PropsWithChildren, ReactNode } from 'react';
import { useTheme } from '@mui/styles';
import { Stack, SxProps, Card as CardMui, CardActionArea } from '@mui/material';
import CardTitle from './CardTitle';
import { Theme } from '../../Theme';
import { Link } from 'react-router-dom';

interface CardProps extends PropsWithChildren {
  title?: ReactNode;
  action?: ReactNode;
  noPadding?: boolean;
  sx?: SxProps;
  titleSx?: SxProps;
  fullHeight?: boolean;
  onClick?: () => void;
  to?: string;
  variant?: 'elevation' | 'outlined';
  disabled?: boolean;
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
  to,
  variant,
  disabled,
}: CardProps) => {
  const theme = useTheme<Theme>();

  const containerPadding = !noPadding && !onClick && !to;

  const containerSx: SxProps = {
    position: 'relative',
    flexGrow: fullHeight ? 1 : 0,
    padding: containerPadding ? theme.spacing(3) : 0,
    borderRadius: theme.spacing(0.5),
    background: theme.palette.background.secondary,
    ...sx,
  };

  const actionAreaSx: SxProps = {
    padding: noPadding ? 0 : theme.spacing(3),
    height: '100%',
  };

  let content = children;
  if (onClick) {
    content = (
      <CardActionArea disabled={disabled} onClick={onClick} sx={actionAreaSx}>
        {children}
      </CardActionArea>
    );
  } else if (to) {
    content = (
      <CardActionArea disabled={disabled} component={Link} to={to} sx={actionAreaSx}>
        {children}
      </CardActionArea>
    );
  }

  return (
    <Stack sx={{ height: '100%' }}>
      {title && (
        <CardTitle action={action} sx={titleSx}>
          {title}
        </CardTitle>
      )}
      <CardMui elevation={0} sx={containerSx} variant={variant}>
        {content}
      </CardMui>
    </Stack>
  );
};

export default Card;
