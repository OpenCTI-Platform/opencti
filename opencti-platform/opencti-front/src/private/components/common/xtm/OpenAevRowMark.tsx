import React from 'react';
import Box from '@mui/material/Box';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { OaevLogo } from '../../../../static/images/logo_oaev';
import useXtmCounterpart, { XtmCounterpartKind } from './useXtmCounterparts';

interface OpenAevRowMarkProps {
  kind: XtmCounterpartKind;
  // The natural key both platforms share: hostname, MITRE id, CVE id or STIX id.
  counterpartKey: string | null | undefined;
}

/**
 * List-row mark of an object OpenAEV also holds: a small OpenAEV logo linking to the counterpart.
 * Nothing is drawn while loading, without a match or when OpenAEV is not connected, so a list
 * never fills with muted marks or calls to action (the hero carries the CTA). The lookups of
 * every row of a page go out batched in one query per kind.
 */
const OpenAevRowMark: React.FC<OpenAevRowMarkProps> = ({ kind, counterpartKey }) => {
  const { t_i18n } = useFormatter();
  const state = useXtmCounterpart('openaev', kind, counterpartKey);
  if (state.status !== 'match') return null;
  const { object_name, object_url } = state.counterpart;
  const label = object_name ? `${t_i18n('Open in OpenAEV')}: ${object_name}` : t_i18n('Open in OpenAEV');
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Box
          component="a"
          href={object_url}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={t_i18n('Open in OpenAEV')}
          // The row is itself a link: the mark opens OpenAEV without opening the row.
          onClick={(event: React.MouseEvent) => event.stopPropagation()}
          sx={{
            display: 'inline-flex',
            alignItems: 'center',
            flexShrink: 0,
            ml: 0.5,
            verticalAlign: 'middle',
            '& svg': { width: 16, height: 16 },
          }}
        >
          <OaevLogo />
        </Box>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
};

export default OpenAevRowMark;
