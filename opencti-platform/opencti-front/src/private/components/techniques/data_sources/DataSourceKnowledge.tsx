// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent } from 'react';
import { Route, Switch } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import DataSourcePopover from './DataSourcePopover';
import { DataSourceKnowledge_dataSource$key } from './__generated__/DataSourceKnowledge_dataSource.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const DataSourceKnowledgeFragment = graphql`
  fragment DataSourceKnowledge_dataSource on DataSource {
    id
    name
    aliases
  }
`;

interface DataSourceKnowledgeComponentProps {
  data: DataSourceKnowledge_dataSource$key;
  enableReferences: boolean;
}

const DataSourceKnowledgeComponent: FunctionComponent<
DataSourceKnowledgeComponentProps
> = ({ data }) => {
  const classes = useStyles();

  const dataSource = useFragment(DataSourceKnowledgeFragment, data);

  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Data-Source'}
        stixDomainObject={dataSource}
        PopoverComponent={<DataSourcePopover id={dataSource.id} />}
      />
      <Switch>
        <Route
          path="/dashboard/techniques/data_sources/:dataSourceId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship entityId={dataSource.id} {...routeProps} />
          )}
        />
      </Switch>
    </div>
  );
};

export default DataSourceKnowledgeComponent;
