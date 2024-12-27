import React, { useState } from 'react';
import * as R from 'ramda';
import ToggleButton from '@mui/material/ToggleButton';
import { PrecisionManufacturingOutlined } from '@mui/icons-material';
import EETooltip from '../entreprise_edition/EETooltip';
import Drawer from '../drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixCoreObjectEnrollPlaybookLines, { stixCoreObjectEnrollPlaybookLinesQuery } from './StixCoreObjectEnrollPlaybookLines';
import useHelper from '../../../../utils/hooks/useHelper';

const StixCoreObjectEnrollPlaybook = (props) => {
  const { t, stixCoreObjectId, handleClose, open } = props;
  const [openDrawer, setOpenDrawer] = useState(false);

  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const handleOpenEnrollPlaybook = () => {
    setOpenDrawer(true);
  };
  const handleCloseEnrollPlaybook = () => {
    setOpenDrawer(false);
  };
  return (
    <>
      {(isFABReplaced || !handleClose) && (
        <EETooltip title={t('Enroll in playbook')}>
          <ToggleButton
            onClick={handleOpenEnrollPlaybook}
            value="enroll"
            size="small"
            style={{ marginRight: 3 }}
          >
            <PrecisionManufacturingOutlined fontSize="small" color="secondary" />
          </ToggleButton>
        </EETooltip>
      )}
      <Drawer
        open={open || openDrawer}
        onClose={handleClose || handleCloseEnrollPlaybook}
        title={t('Available playbooks')}
      >
        <QueryRenderer
          query={stixCoreObjectEnrollPlaybookLinesQuery}
          variables={{ id: stixCoreObjectId }}
          render={({ props: queryProps }) => {
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

export default R.compose(inject18n)(StixCoreObjectEnrollPlaybook);
