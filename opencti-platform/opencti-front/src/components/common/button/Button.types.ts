export type ButtonSize = 'default' | 'small';
export type ButtonIntent = 'default' | 'destructive' | 'ai';
export type GradientVariant = 'default' | 'ai' | 'disabled';

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

export interface SizeConfig {
  height: string;
  padding: string;
  minWidth: string;
  width: string;
  fontSize: string;
  fontWeight: number;
  lineHeight: string;
  iconSize: string;
}
