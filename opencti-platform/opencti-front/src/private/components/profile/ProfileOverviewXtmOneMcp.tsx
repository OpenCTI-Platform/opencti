import Button from '@common/button/Button';
import Card from '@common/card/Card';
import { ContentCopyOutlined, OpenInNewOutlined } from '@mui/icons-material';
import { IconButton, Stack, Tooltip, Typography } from '@mui/material';
import Label from '../../../components/common/label/Label';
import { useFormatter } from '../../../components/i18n';
import { toSafeHttpUrl } from '../../../utils/url';
import { copyToClipboard } from '../../../utils/utils';
import { useChatbot } from '../chatbox/ChatbotContext';

/**
 * "XTM One MCP server" profile card - shown only when the platform is
 * connected to XTM One (`xtm_one_configured` + `xtm_one_url` from
 * `/chatbot/config`, the same gate as the top-bar CTEM Command Center
 * button).
 *
 * XTM One natively embeds an MCP (Model Context Protocol) server for every
 * registered platform: AI clients (Cursor, Claude Desktop, custom agents)
 * connect to `{xtm_one_url}/mcp/opencti` with a personal XTM One API key and
 * work with the OpenCTI knowledge under the caller's own identity. This card
 * makes that endpoint discoverable from the user's profile, next to the
 * classic API access section.
 */
const ProfileOverviewXtmOneMcp = () => {
  const { t_i18n } = useFormatter();
  let xtmOneConfigured: boolean | null = null;
  let xtmOneUrl: string | null = null;
  try {
    ({ xtmOneConfigured, xtmOneUrl } = useChatbot());
  } catch (_) {
    // Graceful fallback if rendered outside of ChatbotProvider (e.g. tests
    // mounting <Profile /> directly) - same pattern as utils/hooks/useAI.ts.
  }

  const safeXtmOneUrl = toSafeHttpUrl(xtmOneUrl)?.replace(/\/+$/, '') ?? null;
  if (xtmOneConfigured !== true || !safeXtmOneUrl) {
    return null;
  }

  const mcpEndpointUrl = `${safeXtmOneUrl}/mcp/opencti`;
  const xtmOneProfileUrl = `${safeXtmOneUrl}/profile/mcp`;

  return (
    <Card title={t_i18n('XTM One MCP server')}>
      <Typography variant="body1" gutterBottom>
        {t_i18n('This platform is connected to XTM One, which natively exposes an MCP (Model Context Protocol) server for OpenCTI. AI clients such as Cursor or Claude Desktop can search, read and create threat intelligence knowledge with your own permissions.')}
      </Typography>
      <div style={{ marginTop: 16 }}>
        <Label>{t_i18n('MCP endpoint URL')}</Label>
        <Stack direction="row" alignItems="center" gap={1}>
          <pre style={{ flex: 1, minWidth: 0, margin: 0, overflowX: 'auto' }}>{mcpEndpointUrl}</pre>
          <Tooltip title={t_i18n('Copy MCP endpoint URL')}>
            <IconButton
              size="small"
              aria-label={t_i18n('Copy MCP endpoint URL')}
              onClick={() => copyToClipboard(t_i18n, mcpEndpointUrl)}
            >
              <ContentCopyOutlined fontSize="small" />
            </IconButton>
          </Tooltip>
        </Stack>
      </div>
      <Typography variant="body2" style={{ marginTop: 16 }}>
        {t_i18n('Authenticate with a personal XTM One API key passed as a bearer token. Your endpoint, connection status and ready-to-copy client configuration are available in your XTM One profile.')}
      </Typography>
      <Stack direction="row" justifyContent="flex-end" style={{ marginTop: 16 }}>
        <Button
          variant="secondary"
          endIcon={<OpenInNewOutlined />}
          onClick={() => window.open(xtmOneProfileUrl, '_blank', 'noopener,noreferrer')}
        >
          {t_i18n('Manage in XTM One')}
        </Button>
      </Stack>
    </Card>
  );
};

export default ProfileOverviewXtmOneMcp;
