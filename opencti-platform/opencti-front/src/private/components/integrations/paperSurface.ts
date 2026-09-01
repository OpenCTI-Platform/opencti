import type { Theme } from '@mui/material/styles';
import { FDS } from '../../../components/fds-tokens.generated';

const fdsFor = (theme: Theme) => (theme.palette.mode === 'light' ? FDS.colors.light : FDS.colors.dark);

export const paperBg = (theme: Theme) => theme.palette.background.paper;

export const paperBorder = (theme: Theme) => fdsFor(theme)['--border-elevation-subtle-soft'];
