import { RadarOutlined } from '@mui/icons-material';
import { IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { CGUStatus } from '@components/settings/Experience';
import React from 'react';
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
 * Uses the library IconButton in its `ia` variant, so it gets the same shape and
 * hover halo as the other top-bar actions. The `ia` variant tints a label only:
 * the glyph keeps `currentColor`, so it is painted AI purple with the token, like
 * the Ask Ariane icon beside it and the OpenAEV CTEM Command Center button.
 */
const CtemCommandCenterButton = () => {
  const { t_i18n } = useFormatter();
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
    <Tooltip>
      <TooltipTrigger asChild>
        <IconButton
          variant="ia"
          priority="tertiary"
          onClick={() => window.open(safeXtmOneUrl, '_blank', 'noopener,noreferrer')}
          aria-label={t_i18n('CTEM Command Center')}
          icon={<RadarOutlined fontSize="medium" style={{ color: 'var(--color-filigran-ia-primary)' }} />}
        />
      </TooltipTrigger>
      {/* The library tooltip does not lower-case its text, so "CTEM" and
          "XTM One" keep their casing without an opt-out wrapper. */}
      <TooltipContent>{t_i18n('Open CTEM Command Center in XTM One')}</TooltipContent>
    </Tooltip>
  );
};

CtemCommandCenterButton.displayName = 'CtemCommandCenterButton';

export default CtemCommandCenterButton;
