import Button from '@mui/material/Button';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import React, { useContext } from 'react';
import { isNotEmptyField } from '../utils/utils';
import { SYSTEM_BANNER_HEIGHT } from '../public/components/SystemBanners';
import { UserContext } from '../utils/hooks/useAuth';

export const TOP_BANNER_HEIGHT = 30;

const TOPBANNER_COLORS = {
  gradient_blue: { from: '#7dd3fc', to: '#5eead4' },
  gradient_yellow: { from: '#fde68a', to: '#f59e0b' },
  gradient_green: { from: '#6ee7b7', to: '#fef08a' },
  red: { from: '#d0021b', to: '#d0021b' },
  yellow: { from: '#ffecb3', to: '#ffecb3' },
} as const;

export type TopBannerColor = keyof typeof TOPBANNER_COLORS;

interface TopBannerProps {
  bannerText: React.ReactNode;
  bannerColor?: TopBannerColor;
  buttonText: React.ReactNode;
  onButtonClick: () => void;
}

const TopBanner = ({ bannerText, bannerColor = 'gradient_blue', buttonText, onButtonClick }: TopBannerProps) => {
  const { settings } = useContext(UserContext);
  const colors = TOPBANNER_COLORS[bannerColor];

  const platformBannerLevel = settings?.platform_banner_level;
  const platformBannerText = settings?.platform_banner_text;
  const isPlatformBannerActivated = isNotEmptyField(platformBannerLevel) && isNotEmptyField(platformBannerText);

  return (
    <div style={{
      position: 'fixed',
      zIndex: 1202,
      color: '#000000',
      width: '100%',
      padding: 4,
      borderRadius: 0,
      backgroundImage: `linear-gradient(to right, ${colors.from}, ${colors.to})`,
      justifyContent: 'center',
      display: 'flex',
      top: isPlatformBannerActivated ? SYSTEM_BANNER_HEIGHT : 0,
      height: TOP_BANNER_HEIGHT,
    }}
    >
      <span>
        {bannerText}
      </span>
      { buttonText && <Button
        variant="contained"
        onClick={onButtonClick}
        sx={{
          marginLeft: 1,
          backgroundColor: '#ffffff',
          color: '#000000',
          padding: '1px 6px',
          fontSize: '0.8rem',
          textTransform: 'none',
          lineHeight: 1.2,
          '& .MuiButton-endIcon': {
            marginLeft: '2px',
          },
        }}
        endIcon={<ArrowForwardIcon/>}
                      >
        {buttonText}
      </Button>}
    </div>
  );
};

export default TopBanner;
