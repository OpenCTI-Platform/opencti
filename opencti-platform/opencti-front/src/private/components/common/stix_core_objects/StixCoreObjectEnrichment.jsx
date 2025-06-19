import React, { useState } from 'react';
import { CloudRefreshOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import ToggleButton from '@mui/material/ToggleButton';
import Drawer from '../drawer/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectEnrichmentLines, { stixCoreObjectEnrichmentLinesQuery } from './StixCoreObjectEnrichmentLines';

const StixCoreObjectEnrichment = ({ stixCoreObjectId, onClose, isOpen }) => {
  // otherwise, a button + internal state allow to open and close
  const [openDrawer, setOpenDrawer] = useState(false);
  const [search, setSearch] = useState('');

  const { t_i18n } = useFormatter();

  const handleOpenEnrichment = () => {
    setOpenDrawer(true);
  };

  const handleClose = () => {
    setOpenDrawer(false);
    setSearch('');
  };

  return (
    <>
      {!onClose && (
        <Tooltip title={t_i18n('Enrichment')}>
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
        open={isOpen || openDrawer}
        onClose={onClose || handleClose}
        title={t_i18n('Enrichment connectors')}
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
                  search={search}
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

export default StixCoreObjectEnrichment;
