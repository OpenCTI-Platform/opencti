import React, { useEffect, useRef, useState } from 'react';
import DialogActions from '@mui/material/DialogActions';
import { useTheme } from '@mui/styles';
import { Spinner, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import FiligranIcon from '@components/common/FiligranIcon';
import { LogoXtmOneIcon } from 'filigran-icon';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useAuth from '../../../../utils/hooks/useAuth';
import { APP_BASE_PATH } from '../../../../relay/environment';
import { useChatbot } from '../../chatbox/ChatbotContext';
import { type AgentOption, callAgentStream, fetchAgentsForIntent } from '../../../../utils/ai/agentApi';
import { PULSE_BRIEFING_INTENT, type PulsePeriodValue } from './threatPulseUtils';

interface ThreatPulseBriefingProps {
  period: PulsePeriodValue;
  sectorBucket: string | null | undefined;
  regionBucket: string | null | undefined;
}

// The context sent to the Sector Pulse Briefing agent of XTM One: the agent reads the network data itself through
// its OpenCTI tools, under the identity of the user.
export const buildPulseBriefingContext = (props: ThreatPulseBriefingProps, platformUrl: string) => JSON.stringify({
  kind: 'pulse_briefing',
  period: props.period,
  sector_bucket: props.sectorBucket ?? null,
  region_bucket: props.regionBucket ?? null,
  platform_url: platformUrl,
});

/**
 * Weekly sector brief written by the XTM One agent bound to the cti.pulse_briefing intent (Enterprise Edition, XTM One
 * configured). Renders nothing when no agent serves the intent.
 */
const ThreatPulseBriefing = (props: ThreatPulseBriefingProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { settings } = useAuth();
  const { xtmOneConfigured } = useChatbot();
  const [agent, setAgent] = useState<AgentOption | undefined>(undefined);
  const [open, setOpen] = useState(false);
  const [content, setContent] = useState('');
  const [error, setError] = useState<string | undefined>(undefined);
  const [loading, setLoading] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!isEnterpriseEdition || xtmOneConfigured !== true) {
      return;
    }
    fetchAgentsForIntent(PULSE_BRIEFING_INTENT).then((agents) => setAgent(agents[0]));
  }, [isEnterpriseEdition, xtmOneConfigured]);

  useEffect(() => () => abortRef.current?.abort(), []);

  if (!agent) {
    return null;
  }

  const generate = async (forceRefresh: boolean) => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setLoading(true);
    setError(undefined);
    setContent('');
    const response = await callAgentStream(
      agent.slug,
      buildPulseBriefingContext(props, settings.platform_url || `${window.location.origin}${APP_BASE_PATH}`),
      (partial) => setContent(partial),
      controller.signal,
      forceRefresh,
    ).catch((reason: unknown) => ({ content: '', status: 'error' as const, error: String(reason) }));
    if (!controller.signal.aborted) {
      if (response.status === 'error') {
        setError(response.error ?? t_i18n('An unknown error occurred'));
      }
      setLoading(false);
    }
  };

  const handleOpen = () => {
    setOpen(true);
    generate(false);
  };

  const handleClose = () => {
    abortRef.current?.abort();
    setLoading(false);
    setOpen(false);
  };

  return (
    <>
      <Button
        variant="tertiary"
        size="small"
        intent="ai"
        onClick={handleOpen}
        startIcon={<FiligranIcon icon={LogoXtmOneIcon} size={16} />}
        data-testid="threat-pulse-briefing-button"
      >
        {t_i18n('Sector briefing')}
      </Button>
      <Dialog open={open} onClose={handleClose} size="large" title={t_i18n('Sector pulse briefing')} showCloseButton>
        {loading && content.length === 0 && <Spinner label={t_i18n('Writing the briefing')} />}
        {error && <Text variant="content-compact" role="alert" style={{ color: theme.palette.error.main }}>{error}</Text>}
        {content.length > 0 && <MarkdownDisplay content={content} remarkGfmPlugin={true} commonmark={true} />}
        <DialogActions>
          <Button variant="secondary" onClick={() => generate(true)} disabled={loading}>
            {t_i18n('Regenerate')}
          </Button>
          <Button onClick={handleClose}>{t_i18n('Close')}</Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ThreatPulseBriefing;
