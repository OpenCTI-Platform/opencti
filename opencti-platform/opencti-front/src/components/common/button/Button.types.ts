import { ButtonProps as MuiButtonProps } from '@mui/material';

export type ButtonVariant = 'primary' | 'secondary' | 'tertiary' | 'extra';
export type ButtonSize = 'default' | 'small';
export type ButtonIntent = 'default' | 'destructive' | 'ai';
export type GradientVariant = 'default' | 'ai' | 'disabled';

export interface BaseButtonProps extends Omit<MuiButtonProps, 'variant' | 'color' | 'size'> {
  variant?: ButtonVariant;
  intent?: ButtonIntent;
  size?: ButtonSize;
  gradient?: boolean;
  gradientVariant?: GradientVariant;
  gradientStartColor?: string;
  gradientEndColor?: string;
  gradientAngle?: number;
  startIcon?: React.ReactNode;
  endIcon?: React.ReactNode;
  fullWidth?: boolean;
  iconOnly?: boolean;
  component?: React.ElementType;
  to?: string
}

type RestrictedIntentButtonProps = BaseButtonProps & {
  intent: 'destructive' | 'ai';
  variant?: Exclude<ButtonVariant, 'primary'>;
};

// Default buttons can use any variant
type DefaultIntentButtonProps = BaseButtonProps & {
  intent?: 'default';
  variant?: ButtonVariant;
};

export type CustomButtonProps = RestrictedIntentButtonProps | DefaultIntentButtonProps;

export interface ColorDefinition {
  main: string;
  hover: string;
  focus: string;
  text: string;
  border: string;
  borderColor: string
}

export interface GradientColor {
  start: string;
  end: string;
}