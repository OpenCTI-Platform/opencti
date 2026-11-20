import React, { useEffect, useState } from 'react';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../../../components/i18n';
import { OaevLogo } from '../../../../../../static/images/logo_oaev';
import { lookupXtmConnections, lookupXtmCounterpart, normaliseXtmKey, XtmCounterpart } from '../core/useXtmCounterparts';

// An incident or a sighting rarely carries more than a few links; the lookup is batched anyway.
export const OPENAEV_ALERT_MAX_LINKS = 50;

interface OpenAevAlertCardProps {
  // The external reference URLs of the incident or sighting: an alert an OpenAEV collector
  // matched is known there by the same link.
  alertLinks: ReadonlyArray<string | null | undefined>;
  // In an overview grid: the card takes a full-width row of its own, and no empty cell is left
  // when it draws nothing.
  gridRow?: boolean;
}

type AlertMatch = { link: string; counterpart: XtmCounterpart };

/** The OpenAEV injects whose expectations a collected alert answered, one per inject. */
export const useOpenAevAlertMatches = (alertLinks: ReadonlyArray<string | null | undefined>): AlertMatch[] | null => {
  // A link never holds a line break (normalised and trimmed), so the joined list keys the effect.
  const signature = [...new Set(alertLinks
    .map((link) => normaliseXtmKey('ALERT', link))
    .filter((link): link is string => !!link))]
    .slice(0, OPENAEV_ALERT_MAX_LINKS)
    .join('\n');
  const [matches, setMatches] = useState<AlertMatch[] | null>(null);
  useEffect(() => {
    let active = true;
    const links = signature ? signature.split('\n') : [];
    setMatches(null);
    if (links.length === 0) {
      setMatches([]);
      return () => {
        active = false;
      };
    }
    lookupXtmConnections().then((connections) => {
      if (!active) return;
      if (!connections.get('openaev')) {
        setMatches([]);
        return;
      }
      Promise.all(links.map((link) => lookupXtmCounterpart('ALERT', link).then((counterpart) => ({ link, counterpart }))))
        .then((results) => {
          if (!active) return;
          const seen = new Set<string>();
          const found: AlertMatch[] = [];
          results.forEach(({ link, counterpart }) => {
            if (counterpart && counterpart.product === 'openaev' && !seen.has(counterpart.object_id)) {
              seen.add(counterpart.object_id);
              found.push({ link, counterpart });
            }
          });
          setMatches(found);
        });
    });
    return () => {
      active = false;
    };
  }, [signature]);
  return matches;
};

/**
 * Overview card "In OpenAEV" of an incident or a sighting: the simulation injects whose
 * detection or prevention expectation an alert of this incident answered, each with
 * "Investigate in OpenAEV". Most incidents never come from a simulation, so nothing is drawn
 * without a match, while loading, or when OpenAEV is not connected: no muted line and no call to
 * action on every incident of the platform.
 */
const OpenAevAlertCard: React.FC<OpenAevAlertCardProps> = ({ alertLinks, gridRow = false }) => {
  const { t_i18n } = useFormatter();
  const matches = useOpenAevAlertMatches(alertLinks);
  if (!matches || matches.length === 0) return null;

  const card = (
    <Card title={t_i18n('In OpenAEV')}>
      <Stack spacing={1.5} data-testid="openaev-alert-card">
        {matches.map(({ link, counterpart }) => (
          <Stack key={counterpart.object_id} direction="row" spacing={1.5} sx={{ alignItems: 'center' }}>
            <Box aria-hidden sx={{ display: 'inline-flex', flexShrink: 0, '& svg': { width: 24, height: 24 } }}>
              <OaevLogo />
            </Box>
            <Box sx={{ minWidth: 0, flexGrow: 1 }}>
              <Box
                title={counterpart.object_name ?? undefined}
                sx={{ typography: 'body2', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
              >
                {counterpart.object_name ?? t_i18n('Simulation inject')}
              </Box>
              <Box
                title={link}
                sx={{ typography: 'caption', color: 'text.secondary', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
              >
                {`${t_i18n('Alert expected by this inject')}: ${link}`}
              </Box>
            </Box>
            <Button
              variant="secondary"
              size="small"
              href={counterpart.object_url}
              target="_blank"
              rel="noopener noreferrer"
            >
              {t_i18n('Investigate in OpenAEV')}
            </Button>
          </Stack>
        ))}
      </Stack>
    </Card>
  );
  return gridRow ? <Grid size={12}>{card}</Grid> : card;
};

export default OpenAevAlertCard;
