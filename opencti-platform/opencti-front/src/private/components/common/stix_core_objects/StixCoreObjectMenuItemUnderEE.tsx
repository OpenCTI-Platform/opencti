import MenuItem from '@mui/material/MenuItem';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import React, { FunctionComponent } from 'react';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import Security from '../../../../utils/Security';

interface StixCoreObjectMenuItemUnderEEProps {
  setOpen: (v: boolean) => void,
  handleCloseMenu?: () => void,
  title: string,
  isDisabled?: boolean,
  needs?: string[]
  matchAll?: boolean
}

const StixCoreObjectMenuItemUnderEE: FunctionComponent<StixCoreObjectMenuItemUnderEEProps> = ({
  setOpen,
  handleCloseMenu,
  title,
  needs,
  matchAll,
  isDisabled = false,
}) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const isEnterpriseEdition = useEnterpriseEdition();
  const isActionPossible = !draftContext && isEnterpriseEdition && !isDisabled;

  let tooltipContent: string | undefined;
  if (draftContext) {
    tooltipContent = t_i18n('Not available in draft');
  } else if (!isEnterpriseEdition) {
    tooltipContent = t_i18n('Only available in EE');
  } else if (isDisabled) {
    tooltipContent = t_i18n('You are not allowed to do this');
  }

  return (
    <Security needs={needs ?? []} matchAll={matchAll}>
      <EETooltip title={tooltipContent}>
        <span>
          <MenuItem
            onClick={() => {
              setOpen(true);
              handleCloseMenu?.();
            }}
            disabled={!isActionPossible}
          >
            {title}
          </MenuItem>
        </span>
      </EETooltip>
    </Security>
  );
};

export default StixCoreObjectMenuItemUnderEE;
