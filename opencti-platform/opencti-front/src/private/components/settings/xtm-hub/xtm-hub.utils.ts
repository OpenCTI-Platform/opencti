import type { Theme } from 'src/components/Theme';
import xtmHubDark from '../../../../static/images/xtm/xtm_hub_dark.png';
import xtmHubLight from '../../../../static/images/xtm/xtm_hub_light.png';

export const getXtmHubLogo = (theme: Theme) => (theme.palette.mode === 'dark' ? xtmHubDark : xtmHubLight);

export const getChipStyle = (theme: Theme) => ({
  fontSize: theme.typography.body2.fontSize,
  fontWeight: theme.typography.fontWeightMedium,
  borderRadius: theme.shape.borderRadius,
  height: theme.spacing(3),
}) as const;
