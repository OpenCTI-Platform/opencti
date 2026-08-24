import React from 'react';
import { InformationOutline } from 'mdi-material-ui';
import { IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import useHelper from '../../../utils/hooks/useHelper';
import { GARBAGE_COLLECTION_MANAGER } from '../../../utils/platformModulesHelper';

/**
 * The information beside the trash breadcrumb.
 *
 * The trigger is a real button, not the bare icon this page used to render.
 * The library's `adornment` slot places anything FOCUSABLE after the last link
 * in the tab order so a tooltip on it is keyboard-reachable — an `<svg>` is not
 * focusable and carries no accessible name, so the three sentences below were
 * reachable by pointer only. Same shape as the slot's own documented example
 * and as this product's other library tooltips: trigger `asChild`, the button
 * named, the text in the content.
 *
 * No `onClick`: the button exists to be focused and described, and the tooltip
 * is what it discloses.
 */
const TrashInformation = () => {
  const { t_i18n } = useFormatter();
  const { isModuleEnable } = useHelper();
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <IconButton
          size="sm"
          priority="tertiary"
          aria-label={t_i18n('More information')}
          icon={<InformationOutline fontSize="small" aria-hidden />}
          className="ml-2"
        />
      </TooltipTrigger>
      <TooltipContent>
        {t_i18n('Entities and relationships manually deleted from the platform will appear in this view, and can be restored.')}
        <br />
        {t_i18n('Elements deleted by connectors or during platform synchronization are not put into the trash.')}
        {isModuleEnable(GARBAGE_COLLECTION_MANAGER) && (
          <>
            <br />
            {t_i18n('An element will persist in the trash for a fixed period of time before being permanently deleted, according to the garbage collection manager settings.')}
          </>
        )}
      </TooltipContent>
    </Tooltip>
  );
};

export default TrashInformation;
