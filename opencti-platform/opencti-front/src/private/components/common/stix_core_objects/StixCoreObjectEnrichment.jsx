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
  const { t, stixCoreObjectId } = props;
  // otherwise, a button + internal state allow to open and close
  const [openDrawer, setOpenDrawer] = useState(false);
  const [search, setSearch] = useState('');

  const handleOpenEnrichment = () => {
    setOpenDrawer(true);
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
        open={openDrawer}
        onClose={() => { setOpenDrawer(false); setSearch(''); }}
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

export default R.compose(inject18n)(StixCoreObjectEnrichment);
