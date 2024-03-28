import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNGETEXPORT_KNASKEXPORT } from 'src/utils/hooks/useGranted';
import { makeStyles } from '@mui/styles';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectsExportsContent, { stixDomainObjectsExportsContentQuery } from './StixDomainObjectsExportsContent';
import {
  StixDomainObjectsExportsContentRefetchQuery$data,
  StixDomainObjectsExportsContentRefetchQuery$variables,
} from './__generated__/StixDomainObjectsExportsContentRefetchQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import StixDomainObjectsExportCreation from './StixDomainObjectsExportCreation';

const useStyles = makeStyles(() => ({
  header: {
    float: 'right',
    marginRight: '10px',
    width: '100%',
    display: 'flex',
    justifyContent: 'flex-end',
  },
}));

interface StixDomainObjectsExportsProps {
  exportContext: { entity_id?: string; entity_type: string };
  paginationOptions: StixDomainObjectsExportsContentRefetchQuery$variables;
  open: boolean;
  handleToggle: () => void;
}

const StixDomainObjectsExports: FunctionComponent<
StixDomainObjectsExportsProps
> = ({ exportContext, paginationOptions, open, handleToggle }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  return (
    <Drawer
      open={open}
      onClose={handleToggle}
      title={t_i18n('Exports list')}
      header={<div className={classes.header}>
        <Security needs={[KNOWLEDGE_KNGETEXPORT_KNASKEXPORT]}>
          <StixDomainObjectsExportCreation
            // data={data}
            exportContext={exportContext}
            paginationOptions={paginationOptions}
            // onExportAsk={() => this.props.relay.refetch({ count: 25, exportContext: this.props.exportContext })}
          />
        </Security>
      </div>}
    >
      <QueryRenderer
        query={stixDomainObjectsExportsContentQuery}
        variables={{ count: 25, exportContext }}
        render={({
          props,
        }: {
          props: StixDomainObjectsExportsContentRefetchQuery$data;
        }) => (
          <StixDomainObjectsExportsContent
            handleToggle={handleToggle}
            data={props}
            paginationOptions={paginationOptions}
            exportContext={exportContext}
            isOpen={open}
          />
        )}
      />
    </Drawer>
  );
};

export default StixDomainObjectsExports;
