import React, { FunctionComponent, useState } from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import { PrecisionManufacturingOutlined } from '@mui/icons-material';
import { StixCoreObjectEnrollPlaybookLinesQuery$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectEnrollPlaybookLinesQuery.graphql';
import EETooltip from '../entreprise_edition/EETooltip';
import Drawer from '../drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import StixCoreObjectEnrollPlaybookLines, { stixCoreObjectEnrollPlaybookLinesQuery } from './StixCoreObjectEnrollPlaybookLines';
import { useFormatter } from '../../../../components/i18n';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import useHelper from '../../../../utils/hooks/useHelper';

interface StixCoreObjectEnrollPlaybookLinesProps {
  stixCoreObjectId: string,
  handleClose: () => void,
  open: boolean,
}

const StixCoreObjectEnrollPlaybook: FunctionComponent<StixCoreObjectEnrollPlaybookLinesProps> = ({ stixCoreObjectId, handleClose, open }) => {
  const [openDrawer, setOpenDrawer] = useState(false);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const disabledInDraft = !!draftContext;

  const handleOpenEnrollPlaybook = () => {
    setOpenDrawer(true);
  };
  const handleCloseEnrollPlaybook = () => {
    setOpenDrawer(false);
  };
  return (
    <>
      {(isFABReplaced || !handleClose) && (
        <EETooltip title={disabledInDraft ? t_i18n('Not available in draft') : t_i18n('Enroll in playbook')}>
          <ToggleButton
            onClick={() => !disabledInDraft && handleOpenEnrollPlaybook()}
            value="enroll"
            size="small"
            style={{ marginRight: 3 }}
          >
            <PrecisionManufacturingOutlined fontSize="small" color={disabledInDraft ? 'disabled' : 'secondary' }/>
          </ToggleButton>
        </EETooltip>
      )}
      <Drawer
        open={open || openDrawer}
        onClose={handleClose || handleCloseEnrollPlaybook}
        title={t_i18n('Available playbooks')}
      >
        <QueryRenderer
          query={stixCoreObjectEnrollPlaybookLinesQuery}
          variables={{ id: stixCoreObjectId }}
          render={({ props: queryProps }: { props: StixCoreObjectEnrollPlaybookLinesQuery$data }) => {
            if (queryProps && queryProps.playbooksForEntity) {
              return (
                <StixCoreObjectEnrollPlaybookLines id={stixCoreObjectId} playbooksForEntity={queryProps.playbooksForEntity} />
              );
            }
            return <div />;
          }}
        />
      </Drawer>
    </>
  );
};

export default StixCoreObjectEnrollPlaybook;
