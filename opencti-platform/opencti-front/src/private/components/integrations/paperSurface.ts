import type { Theme } from '@mui/material/styles';
import { FDS } from '../../../components/fds-tokens.generated';

/**
 * The library `Paper`'s own surface, for the integration boxes that are not
 * converted to `<Paper>` yet.
 *
 * The visual pass asks these to "add the library paper, or at least simulate
 * the same style (bg + border)". Simulating is what this is: the two values
 * below are the ones the shipped `Paper` paints -- `bg-elevation-default` and
 * `border-elevation-subtle-soft`, read off the component's own build -- rather
 * than an eyeballed approximation of them. They live in one place so the
 * structural conversion later is a find-and-replace on this helper, not on
 * fourteen sites.
 *
 * What they replace is `alpha(theme.palette.text.primary, 0.08)` over
 * `background.paper`: a border derived from the TEXT colour, which is why these
 * boxes never quite matched a real Paper.
 */
const fdsFor = (theme: Theme) => (theme.palette.mode === 'light' ? FDS.colors.light : FDS.colors.dark);

/** Background of a library Paper. */
export const paperBg = (theme: Theme) => fdsFor(theme)['--bg-elevation-default'];

/** Border colour of a library Paper — pass it to `border`/`borderBottom`. */
export const paperBorder = (theme: Theme) => fdsFor(theme)['--border-elevation-subtle-soft'];
