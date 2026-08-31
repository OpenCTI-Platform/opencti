import React from 'react';
import { InformationOutline } from 'mdi-material-ui';
import { IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import useHelper from '../../../utils/hooks/useHelper';
import { GARBAGE_COLLECTION_MANAGER } from '../../../utils/platformModulesHelper';

/**
 * The information beside the trash breadcrumb.
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
