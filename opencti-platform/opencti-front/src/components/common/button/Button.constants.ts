import type { ButtonSize } from './Button.types';

interface SizeConfig {
  height: string;
  padding: string;
  minWidth: string;
  width: string;
  fontSize: string;
  fontWeight: number;
  lineHeight: string;
  iconSize: string;
}

export const SIZE_CONFIG: Record<ButtonSize, SizeConfig> = {
  default: {
    height: '36px',
    padding: '0px 16px',
    minWidth: '36px',
    width: '36px',
    fontSize: '14px',
    fontWeight: 600,
    lineHeight: '21px',
    iconSize: '16px',
  },
  small: {
    height: '26px',
    padding: '4px 12px',
    minWidth: '26px',
    width: '26px',
    fontSize: '13px',
    fontWeight: 600,
    lineHeight: '21px',
    iconSize: '14px',
  },
};

export const getSizeConfig = (size: ButtonSize, iconOnly: boolean) => {
  const config = SIZE_CONFIG[size];
  
  return {
    ...config,
    padding: iconOnly ? '0' : config.padding,
    minWidth: iconOnly ? config.minWidth : '64px',
    width: iconOnly ? config.width : 'auto',
  };
};