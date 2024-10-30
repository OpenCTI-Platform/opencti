import React, { useState } from 'react';
import * as R from 'ramda';
import { CloudRefreshOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import Drawer from '../drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixCoreObjectEnrichmentLines, { stixCoreObjectEnrichmentLinesQuery } from './StixCoreObjectEnrichmentLines';

const StixCoreObjectEnrichment = (props) => {
  const { t, stixCoreObjectId, handleClose, open } = props;
  const [openDrawer, setOpenDrawer] = useState(false);

  const handleOpenEnrichment = () => {
    if (props.closeMenu) {
      props.closeMenu();
    }
    setOpenDrawer(true);
  };

  const handleCloseEnrichment = () => {
    setOpenDrawer(false);
  };

  return (
    <>
      <Tooltip title={t('Enrichment')}>
        <ToggleButton
          onClick={handleOpenEnrichment}
          value="enrich"
          size="small"
          style={{ marginRight: 3 }}
        >
          <CloudRefreshOutline fontSize="small" color="primary" />
        </ToggleButton>
      </Tooltip>
      <Drawer
        open={open || openDrawer}
        onClose={handleClose || handleCloseEnrichment}
        title={t('Enrichment connectors')}
      >
        <QueryRenderer
          query={stixCoreObjectEnrichmentLinesQuery}
          variables={{ id: stixCoreObjectId }}
          render={({ props: queryProps }) => {
            if (
              queryProps
              && queryProps.stixCoreObject
              && queryProps.connectorsForImport
            ) {
              return (
                <StixCoreObjectEnrichmentLines
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

export default R.compose(inject18n)(StixCoreObjectEnrichment);
