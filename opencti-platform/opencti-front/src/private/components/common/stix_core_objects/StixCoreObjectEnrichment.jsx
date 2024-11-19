import React, { useState } from 'react';
import * as R from 'ramda';
import { CloudRefreshOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import useHelper from '../../../../utils/hooks/useHelper';
import Drawer from '../drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixCoreObjectEnrichmentLines, { stixCoreObjectEnrichmentLinesQuery } from './StixCoreObjectEnrichmentLines';

const StixCoreObjectEnrichment = (props) => {
  // this component can be controlled with props open and handleClose
  const { t, stixCoreObjectId, handleClose, open } = props;
  // otherwise, a button + internal state allow to open and close
  const [openDrawer, setOpenDrawer] = useState(false);

  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const handleOpenEnrichment = () => {
    setOpenDrawer(true);
  };
  const handleCloseEnrichment = () => {
    setOpenDrawer(false);
  };

  return (
    <>
      {(isFABReplaced || !handleClose) && (
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
      )}
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
