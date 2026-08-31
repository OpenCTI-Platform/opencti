import type { Theme } from '@mui/material/styles';
import { FDS } from '../../../components/fds-tokens.generated';

/**
 * The library `Paper`'s own surface, for the integration boxes that are not converted to
 * `<Paper>` yet.
 */
const fdsFor = (theme: Theme) => (theme.palette.mode === 'light' ? FDS.colors.light : FDS.colors.dark);

/**
 * Background of an integration box.
 */
export const paperBg = (theme: Theme) => theme.palette.background.paper;

/** Border colour of a library Paper — pass it to `border`/`borderBottom`. */
export const paperBorder = (theme: Theme) => fdsFor(theme)['--border-elevation-subtle-soft'];
