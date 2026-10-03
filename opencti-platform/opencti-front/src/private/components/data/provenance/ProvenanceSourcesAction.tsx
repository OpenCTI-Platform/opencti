import React, { useState } from 'react';
import { SourceBranch } from 'mdi-material-ui';
import IconButton from '@common/button/IconButton';
import Drawer from '@components/common/drawer/Drawer';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import ProvenanceSourcesPanel from '../../common/provenance/ProvenanceSourcesPanel';

interface ProvenanceSourcesActionProps {
  id: string;
  onChange?: () => void;
}

/**
 * Row action opening the Sources panel of an element (adopt or dismiss conflicting values, confirm freshness).
 */
const ProvenanceSourcesAction = ({ id, onChange }: ProvenanceSourcesActionProps) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <IconButton
            variant="tertiary"
            size="small"
            aria-label={t_i18n('View sources')}
            onClick={(event: React.MouseEvent) => {
              event.preventDefault();
              event.stopPropagation();
              setOpen(true);
            }}
            data-testid="provenance-row-sources"
          >
            <SourceBranch fontSize="small" />
          </IconButton>
        </TooltipTrigger>
        <TooltipContent>{t_i18n('View sources')}</TooltipContent>
      </Tooltip>
      <Drawer title={t_i18n('Sources')} open={open} onClose={() => setOpen(false)}>
        {open ? <ProvenanceSourcesPanel id={id} onChange={onChange} /> : null}
      </Drawer>
    </>
  );
};

export default ProvenanceSourcesAction;
