import Button from '@common/button/Button';
import React, { useContext, useState } from 'react';
import { isNotEmptyField } from '../utils/utils';
import { SYSTEM_BANNER_HEIGHT } from '../public/components/SystemBanners';
import { UserContext } from '../utils/hooks/useAuth';
import { IconButton, SxProps } from '@mui/material';
import { ChevronRight, Close } from '@mui/icons-material';
import useBus, { dispatch } from '../utils/hooks/useBus';

export const TOP_BANNER_HEIGHT = 30;

// -- Component --

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
  buttonText?: React.ReactNode;
  buttonSx?: SxProps;
  onButtonClick?: () => void;
  dismissible?: boolean;
  /** localStorage key used to persist dismissed state. Required when dismissible=true. */
  dismissKey?: string;
  /** Bus channel used to broadcast dismissed state. Required when dismissible=true. */
  dismissBus?: string;
}

const TopBanner = ({
  bannerText,
  bannerColor = 'gradient_blue',
  buttonText,
  onButtonClick,
  buttonSx,
  dismissible,
  dismissKey,
  dismissBus,
}: TopBannerProps) => {
  const { settings } = useContext(UserContext);
  const colors = TOPBANNER_COLORS[bannerColor];

  const [isDismissed, setIsDismissed] = useState<boolean>(() => {
    if (!dismissible || !dismissKey) return false;
    return localStorage.getItem(dismissKey) === 'true';
  });

  // Always call the hook (rules of hooks), but only act when dismissible and a bus is configured.
  useBus(dismissBus ?? '', (value: boolean) => {
    if (dismissible) setIsDismissed(value);
  }, [dismissible]);

  const handleDismiss = () => {
    if (!dismissKey || !dismissBus) return;
    localStorage.setItem(dismissKey, 'true');
    dispatch(dismissBus, true);
  };

  const platformBannerLevel = settings?.platform_banner_level;
  const platformBannerText = settings?.platform_banner_text;
  const isPlatformBannerActivated = isNotEmptyField(platformBannerLevel) && isNotEmptyField(platformBannerText);

  if (isDismissed) return null;

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
      alignItems: 'center',
      display: 'flex',
      top: (isPlatformBannerActivated ? SYSTEM_BANNER_HEIGHT : 0),
      height: TOP_BANNER_HEIGHT,
    }}
    >
      <span>
        {bannerText}
      </span>
      {buttonText && (
        <Button
          onClick={onButtonClick}
          sx={{
            marginLeft: 1,
            height: '24px',
            backgroundColor: '#ffffff',
            color: '#000000',
            padding: '1px 6px',
            textTransform: 'none',
            '& .MuiButton-endIcon': {
              marginLeft: '2px',
            },
            ...buttonSx,
          }}
          endIcon={<ChevronRight />}
        >
          {buttonText}
        </Button>
      )}
      {dismissible && (
        <IconButton
          aria-label="close"
          size="small"
          onClick={handleDismiss}
          style={{ position: 'absolute', right: 8, color: '#000000' }}
        >
          <Close fontSize="inherit" />
        </IconButton>
      )}
    </div>
  );
};

export default TopBanner;
