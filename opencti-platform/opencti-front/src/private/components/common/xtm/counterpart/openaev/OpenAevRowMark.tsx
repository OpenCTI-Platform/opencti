import React from 'react';
import Box from '@mui/material/Box';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../../../components/i18n';
import { OaevLogo } from '../../../../../../static/images/logo_oaev';
import useXtmCounterpart from '../core/useXtmCounterparts';
import { XtmPivotPreview } from '../core/XtmPivotPreview';
import { OPENAEV_FACTS, previewFactsOf } from '../core/counterpartFacts';

interface OpenAevRowMarkProps {
  // The OpenCTI object of the row: the server reads its key under the caller's rights.
  objectId: string | null | undefined;
}

/**
 * List-row mark of an object OpenAEV also holds: a small OpenAEV logo linking to the counterpart,
 * with the counterpart preview on hover and focus.
 * Nothing is drawn while loading, without a match, when OpenAEV is unavailable or not connected,
 * so a list never fills with muted marks or calls to action (the hero carries the CTA). The lookups
 * of every row of a page go out batched in one query, whatever their type.
 */
const OpenAevRowMark: React.FC<OpenAevRowMarkProps> = ({ objectId }) => {
  const { t_i18n, n, fd } = useFormatter();
  const state = useXtmCounterpart('openaev', objectId);
  if (state.status !== 'match') return null;
  const { counterpart } = state;
  const { object_url } = counterpart;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Box
          component="a"
          href={object_url}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={t_i18n('Open in OpenAEV')}
          data-testid="openaev-row-mark"
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
      <TooltipContent>
        <XtmPivotPreview
          mark={<OaevLogo />}
          productName="OpenAEV"
          entityType={counterpart.object_type}
          name={counterpart.object_name}
          facts={previewFactsOf(counterpart.facts, OPENAEV_FACTS, { t_i18n, count: (v) => n(v), money: (v) => n(v), date: (v) => fd(v) })}
          action={t_i18n('See the simulations, findings and exposed assets of this object in OpenAEV.')}
        />
      </TooltipContent>
    </Tooltip>
  );
};

export default OpenAevRowMark;
