// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { FunctionComponent } from 'react';
import { Route, Switch } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import DataComponentPopover from './DataComponentPopover';
import { DataComponentKnowledge_dataComponent$key } from './__generated__/DataComponentKnowledge_dataComponent.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const DataComponentKnowledgeFragment = graphql`
  fragment DataComponentKnowledge_dataComponent on DataComponent {
    id
    name
    aliases
  }
`;

interface DataComponentKnowledgeProps {
  data: DataComponentKnowledge_dataComponent$key;
  enableReferences: boolean;
}

const DataComponentKnowledge: FunctionComponent<
DataComponentKnowledgeProps
> = ({ data }) => {
  const classes = useStyles();

  const dataComponent = useFragment(DataComponentKnowledgeFragment, data);

  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Data-Component'}
        stixDomainObject={dataComponent}
        PopoverComponent={
          <DataComponentPopover dataComponentId={dataComponent.id} />
        }
      />
      <Switch>
        <Route
          path="/dashboard/techniques/data_components/:dataComponentId/knowledge/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship entityId={dataComponent.id} {...routeProps} />
          )}
        />
      </Switch>
    </div>
  );
};

export default DataComponentKnowledge;
