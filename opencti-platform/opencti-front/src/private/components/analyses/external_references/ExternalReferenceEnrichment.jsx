import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { CloudRefreshOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import ExternalReferenceEnrichmentLines, { externalReferenceEnrichmentLinesQuery } from './ExternalReferenceEnrichmentLines';
import Drawer from '../../common/drawer/Drawer';

const ExternalReferenceEnrichment = ({ externalReferenceId }) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  return (
    <div style={{ display: 'inline-block' }}>
      <Tooltip title={t_i18n('Enrichment')}>
        <IconButton
          onClick={() => setOpen(true)}
          color="primary"
          aria-label="Refresh"
          size="large"
        >
          <CloudRefreshOutline />
        </IconButton>
      </Tooltip>
      <Drawer
        open={open}
        onClose={() => setOpen(false)}
        title={t_i18n('Enrichment connectors')}
      >
        <QueryRenderer
          query={externalReferenceEnrichmentLinesQuery}
          variables={{ id: externalReferenceId }}
          render={({ props: queryProps }) => {
            if (
              queryProps
              && queryProps.externalReference
              && queryProps.connectorsForImport
            ) {
              return (
                <ExternalReferenceEnrichmentLines
                  externalReference={queryProps.externalReference}
                  connectorsForImport={queryProps.connectorsForImport}
                />
              );
            }
            return <div />;
          }}
        />
      </Drawer>
    </div>
  );
};

export default ExternalReferenceEnrichment;
