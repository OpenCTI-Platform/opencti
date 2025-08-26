import React from 'react';
import { Box, BoxProps, SvgIconProps, SvgIconTypeMap, Typography, TypographyProps } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { OverridableComponent } from '@mui/material/OverridableComponent';
import type { Theme } from './Theme';

type GradientVariant = 'default' | 'ai';

const DEFAULT_START_COLOR = '#2196f3';
const DEFAULT_END_COLOR = '#21cbf3';

const useGradient = (gradientVariant: GradientVariant) => {
  const theme = useTheme<Theme>();

  let startColor: string;
  let endColor: string;

  switch (gradientVariant) {
    case 'ai':
      startColor = theme.palette.ai.light ?? DEFAULT_START_COLOR;
      endColor = theme.palette.ai.dark ?? DEFAULT_END_COLOR;
      break;
    case 'default':
    default:
      startColor = theme.palette.primary.main ?? DEFAULT_START_COLOR;
      endColor = theme.palette.gradient.main ?? DEFAULT_END_COLOR;
      break;
  }

  return { startColor, endColor };
};

const createGradientStyles = ({ startColor, endColor, reverse = false }: { startColor?: string, endColor?: string, reverse?: boolean }) => {
  const color1 = reverse ? endColor : startColor;
  const color2 = reverse ? startColor : endColor;
  const gradient = `linear-gradient(99.95deg, ${color1} 0%, ${color2} 100%)`;

  return {
    gradient,
    textGradientStyle: {
      background: gradient,
      backgroundClip: 'text',
      WebkitBackgroundClip: 'text',
      WebkitTextFillColor: 'transparent',
    },
    iconGradientStyle: {
      '& svg': {
        fill: 'url(#gradient-fill)',
      },
    },
  };
};

interface GradientCardProps extends Omit<BoxProps, 'children'> {
  gradientVariant?: GradientVariant;
  children?: React.ReactNode;
}

const GradientCardRoot = ({
  gradientVariant = 'default',
  children,
  sx,
  ...otherProps
}: GradientCardProps) => {
  const theme = useTheme<Theme>();

  const { startColor, endColor } = useGradient(gradientVariant);

  const { gradient } = createGradientStyles({ startColor, endColor });

  const borderGradientStyle = {
    border: '1px solid transparent',
    borderRadius: 1,
    background: `
      linear-gradient(${theme.palette.background.paper}, ${theme.palette.background.paper}) padding-box,
      ${gradient} border-box
    `,
    boxShadow: `1px 0px 4px -1px ${startColor}, -1px 0px 4px -1px ${endColor}`,
  };

  return (
    <Box
      {...otherProps}
      sx={{
        padding: 4,
        ...borderGradientStyle,
        ...sx,
      }}
    >
      {/* SVG Gradient for icons */}
      <svg width="0" height="0" style={{ position: 'absolute' }}>
        <defs>
          <linearGradient id="gradient-fill" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={startColor} />
            <stop offset="100%" stopColor={endColor} />
          </linearGradient>
        </defs>
      </svg>

      {children}
    </Box>
  );
};

/** *
*
* GradientText
*
** */
interface GradientTextProps extends TypographyProps {
  gradientVariant?: GradientVariant;
}

const GradientText = ({ gradientVariant = 'default', sx, ...props }: GradientTextProps) => {
  const { startColor, endColor } = useGradient(gradientVariant);

  const { textGradientStyle } = createGradientStyles({ startColor, endColor });

  return (
    <Typography
      {...props}
      sx={{
        ...textGradientStyle,
        ...sx,
      }}
    />
  );
};

/** *
*
* GradientIcon
*
** */
interface GradientIconProps {
  icon: OverridableComponent<SvgIconTypeMap> | React.ComponentType<SvgIconProps>;
  size?: 'small' | 'medium' | 'large';
  sx?: object;
}

const GradientIcon = ({ icon: IconComponent, sx }: GradientIconProps) => {
  return (
    <IconComponent
      fontSize="large"
      sx={{
        fill: 'url(#gradient-fill)',
        ...sx,
      }}
    />
  );
};

const GradientCard = Object.assign(GradientCardRoot, {
  Text: GradientText,
  Icon: GradientIcon,
});

export default GradientCard;
