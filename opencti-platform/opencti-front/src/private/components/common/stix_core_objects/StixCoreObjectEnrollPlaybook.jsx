import React, { useState } from 'react';
import * as R from 'ramda';
import { CloudRefreshOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import Drawer from '../drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixCoreObjectEnrollPlaybookLines, { stixCoreObjectEnrollPlaybookLinesQuery } from './StixCoreObjectEnrollPlaybookLines';

const StixCoreObjectEnrollPlaybook = (props) => {
  const { t, stixCoreObjectId, handleClose, open } = props;
  const [openDrawer, setOpenDrawer] = useState(false);
  const handleOpenEnrollPlaybook = () => {
    setOpenDrawer(true);
  };
  const handleCloseEnrollPlaybook = () => {
    setOpenDrawer(false);
  };

  return (
    <>
      {!handleClose && (
        <Tooltip title={t('EnrollPlaybook')}>
          <ToggleButton
            onClick={handleOpenEnrollPlaybook}
            value="enrich"
            size="small"
            style={{ marginRight: 3 }}
          >
            <CloudRefreshOutline fontSize="small" color="primary" />
          </ToggleButton>
        </Tooltip>
      )}
      <Drawer
        open={open || openDrawer}
        onClose={handleClose || handleCloseEnrollPlaybook}
        title={t('EnrollPlaybook connectors')}
      >
        <QueryRenderer
          query={stixCoreObjectEnrollPlaybookLinesQuery}
          variables={{ id: stixCoreObjectId }}
          render={({ props: queryProps }) => {
            if (
              queryProps
              && queryProps.stixCoreObject
              && queryProps.connectorsForImport
            ) {
              return (
                <StixCoreObjectEnrollPlaybookLines
                  stixCoreObject={queryProps.stixCoreObject}
                  connectorsForImport={queryProps.connectorsForImport}
                />
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
