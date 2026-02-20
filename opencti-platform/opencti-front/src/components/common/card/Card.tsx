import { PropsWithChildren, ReactNode } from 'react';
import { useTheme } from '@mui/material/styles';
import { Stack, SxProps, Card as CardMui, CardActionArea, StackProps } from '@mui/material';
import CardTitle from './CardTitle';
import { Theme } from '../../Theme';
import { Link } from 'react-router-dom';
import { hasCustomColor } from '../../../utils/theme';

export interface CardProps extends PropsWithChildren {
  title?: ReactNode;
  action?: ReactNode;
  padding?: 'none' | 'small' | 'horizontal' | 'default';
  sx?: SxProps;
  titleSx?: SxProps;
  titleAlignItems?: StackProps['alignItems'];
  fullHeight?: boolean;
  onClick?: () => void;
  to?: string;
  variant?: 'elevation' | 'outlined';
  disabled?: boolean;
  'aria-label'?: string;
}

const Card = ({
  title,
  children,
  action,
  padding = 'default',
  sx = {},
  titleSx,
  titleAlignItems,
  fullHeight = true,
  onClick,
  to,
  disabled,
  variant,
  ...otherProps
}: CardProps) => {
  const theme = useTheme<Theme>();
  // If no link and no onClick callback then we put the padding on the
  // card container directly, otherwise we put the padding on the
  // CardActionArea component.
  const applyStyleToContainer = !onClick && !to;

  let paddingStyle: SxProps = {
    padding: theme.spacing(3),
  };
  if (padding === 'horizontal') {
    paddingStyle = {
      paddingX: theme.spacing(3),
      paddingY: theme.spacing(1),
    };
  } else if (padding === 'small') {
    paddingStyle = {
      padding: theme.spacing(1),
    };
  } else if (padding === 'none') {
    paddingStyle = {
      padding: 0,
    };
  }

  const isCustomCardColor = hasCustomColor(theme, 'theme_paper');
  const backgroundColor = isCustomCardColor
    ? theme.palette.background.paper
    : theme.palette.background.secondary;

  const containerSx: SxProps = {
    position: 'relative',
    flexGrow: fullHeight ? 1 : 0,
    borderRadius: theme.spacing(0.5),
    background: variant !== 'outlined'
      ? backgroundColor
      : 'transparent',
    ...(applyStyleToContainer ? paddingStyle : {}),
    ...(applyStyleToContainer ? sx : {}),
  };

  const actionAreaSx: SxProps = {
    height: '100%',
    ...paddingStyle,
    ...sx,
  };

  let content = children;
  if (onClick || to) {
    let linkProps = {};
    if (to) {
      linkProps = {
        to,
        component: Link,
      };
    }
    content = (
      <CardActionArea
        disabled={disabled}
        onClick={onClick}
        sx={actionAreaSx}
        {...linkProps}
      >
        {children}
      </CardActionArea>
    );
  }

  return (
    <Stack sx={{ height: '100%' }}>
      {(title || action) && (
        <CardTitle
          action={action}
          sx={titleSx}
          alignItems={titleAlignItems}
        >
          {title}
        </CardTitle>
      )}
      <CardMui
        elevation={0}
        sx={containerSx}
        variant={variant}
        {...otherProps}
      >
        {content}
      </CardMui>
    </Stack>
  );
};

export default Card;
