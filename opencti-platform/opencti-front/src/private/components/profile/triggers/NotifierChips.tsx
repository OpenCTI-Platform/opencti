import React, { FunctionComponent } from 'react';
import { Stack } from '@mui/material';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

interface NotifierChipsProps {
  notifiers: ReadonlyArray<{ readonly id: string; readonly name: string }> | null | undefined;
}

const NotifierChips: FunctionComponent<NotifierChipsProps> = ({ notifiers }) => (
  <FieldOrEmpty source={notifiers}>
    <Tooltip>
      <TooltipTrigger asChild>
        <Stack direction="row" gap={1} flexWrap="nowrap" overflow="hidden">
          {(notifiers ?? []).map((n) => (
            <Chip key={n.id} label={n.name} />
          ))}
        </Stack>
      </TooltipTrigger>
      <TooltipContent>{(notifiers ?? []).map((n) => n.name).join(', ')}</TooltipContent>
    </Tooltip>
  </FieldOrEmpty>
);

export default NotifierChips;
