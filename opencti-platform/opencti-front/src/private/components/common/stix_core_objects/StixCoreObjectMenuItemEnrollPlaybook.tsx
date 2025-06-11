import MenuItem from '@mui/material/MenuItem';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import React, { FunctionComponent } from 'react';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { KNOWLEDGE_KNENRICHMENT } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

interface StixCoreObjectMenuItemEnrollPlaybookProps {
  setOpenEnrollPlaybook: (v: boolean) => void,
  handleCloseMenu?: () => void,
}

const StixCoreObjectMenuItemEnrollPlaybook: FunctionComponent<StixCoreObjectMenuItemEnrollPlaybookProps> = ({
  setOpenEnrollPlaybook,
  handleCloseMenu,
}) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const isEnterpriseEdition = useEnterpriseEdition();
  const isEnrollPlaybookPossible = !draftContext && isEnterpriseEdition;
  let title = t_i18n('Enroll in playbook');
  if (draftContext) title = t_i18n('Not available in draft');
  if (!isEnrollPlaybookPossible) t_i18n('Only available in EE');

  return (
    <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
      <EETooltip title={title}>
        <span>
          <MenuItem
            onClick={() => {
              setOpenEnrollPlaybook(true);
              handleCloseMenu?.();
            }}
            disabled={!isEnrollPlaybookPossible}
          >
            {t_i18n('Enroll in playbook')}
          </MenuItem>
        </span>
      </EETooltip>
    </Security>
  );
};

export default StixCoreObjectMenuItemEnrollPlaybook;
