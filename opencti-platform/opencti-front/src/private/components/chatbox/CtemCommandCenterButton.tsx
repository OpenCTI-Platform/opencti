import { RadarOutlined } from '@mui/icons-material';
import { Box, Tooltip } from '@mui/material';
import { useTheme } from '@mui/styles';
import IconButton from '@common/button/IconButton';
import { CGUStatus } from '@components/settings/Experience';
import React from 'react';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import { toSafeHttpUrl } from '../../../utils/url';
import { useChatbot } from './ChatbotContext';

/**
 * Top-bar shortcut to the XTM One CTEM Command Center (the cross-product exposure
 * posture dashboard / XTM One home). Opens the XTM One URL in a new tab.
 *
 * Shown only when XTM One is connected properly (url + token configured, surfaced
 * by `/chatbot/config` as `xtm_one_configured` + `xtm_one_url`) and the agentic
 * AI is not disabled. NOT Enterprise-gated: the CTEM Command Center is also
 * available in full CE (metrics only).
 *
 * Uses the shared top-bar IconButton (tertiary) so it gets the exact same shape
 * and hover halo as the other top-bar actions; only the glyph is AI-tinted.
 */
const CtemCommandCenterButton = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { settings: { filigran_chatbot_ai_cgu_status } } = useAuth();
  const { xtmOneConfigured, xtmOneUrl } = useChatbot();

  const safeXtmOneUrl = toSafeHttpUrl(xtmOneUrl);
  if (
    filigran_chatbot_ai_cgu_status === CGUStatus.disabled
    || xtmOneConfigured !== true
    || !safeXtmOneUrl
  ) {
    return null;
  }

  return (
    <Tooltip
      title={(
        // The global MuiTooltip theme lower-cases tooltip text (sentence case),
        // which would mangle the "CTEM" / "XTM One" acronyms - opt this one out so
        // the product name keeps its true casing.
        <Box component="span" sx={{ textTransform: 'none' }}>
          {t_i18n('Open CTEM Command Center in XTM One')}
        </Box>
      )}
    >
      <IconButton
        size="default"
        onClick={() => window.open(safeXtmOneUrl, '_blank', 'noopener,noreferrer')}
        aria-label={t_i18n('CTEM Command Center')}
      >
        <RadarOutlined fontSize="medium" sx={{ color: theme.palette.ai.main }} />
      </IconButton>
    </Tooltip>
  );
};

CtemCommandCenterButton.displayName = 'CtemCommandCenterButton';

export default CtemCommandCenterButton;
