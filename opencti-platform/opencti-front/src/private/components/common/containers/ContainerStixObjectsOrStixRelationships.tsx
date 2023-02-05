import React, { FunctionComponent, useContext } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import { QueryRenderer } from '../../../../relay/environment';
import ContainerStixObjectsOrStixRelationshipsLines, {
  ContainerStixObjectsOrStixRelationshipsLinesQuery,
} from './ContainerStixObjectsOrStixRelationshipsLines';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import ContainerAddStixCoreObjects from './ContainerAddStixCoreObjects';
import {
  ContainerStixObjectsOrStixRelationshipsLinesQuery$data,
  ContainerStixObjectsOrStixRelationshipsLinesQuery$variables,
} from './__generated__/ContainerStixObjectsOrStixRelationshipsLinesQuery.graphql';
import { ContainerStixObjectsOrStixRelationships_container$data } from './__generated__/ContainerStixObjectsOrStixRelationships_container.graphql';
import { UserContext } from '../../../../utils/hooks/useAuth';
import useGranted, {
  KNOWLEDGE_KNPARTICIPATE,
  KNOWLEDGE_KNUPDATE,
} from '../../../../utils/hooks/useGranted';
import { ContainerStixObjectOrStixRelationshipLineDummy } from './ContainerStixObjectOrStixRelationshipLine';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-5px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
}));

interface ContainerStixObjectsOrStixRelationshipsComponentProps {
  types?: string[];
  isSupportParticipation: boolean;
  container: ContainerStixObjectsOrStixRelationships_container$data;
  paginationOptions?: ContainerStixObjectsOrStixRelationshipsLinesQuery$variables;
}

const ContainerStixObjectsOrStixRelationshipsComponent: FunctionComponent<
ContainerStixObjectsOrStixRelationshipsComponentProps
> = ({
  container,
  paginationOptions,
  isSupportParticipation = false,
  types,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const { me } = useContext(UserContext);
  const security = [KNOWLEDGE_KNUPDATE];
  const isContainerOwner = userIsKnowledgeEditor || me?.individual_id === container.createdBy?.id;
  if (isSupportParticipation && isContainerOwner) {
    security.push(KNOWLEDGE_KNPARTICIPATE);
  }
  const { helper } = useContext(UserContext);
  const isRuntimeSort = helper?.isRuntimeFieldEnable();
  const dataColumns = {
    entity_type: {
      label: 'Type',
      width: '12%',
      isSortable: true,
    },
    name: {
      label: 'Name',
      width: '25%',
      isSortable: true,
    },
    createdBy: {
      label: 'Author',
      width: '12%',
      isSortable: isRuntimeSort ?? false,
    },
    creator: {
      label: 'Creator',
      width: '12%',
      isSortable: isRuntimeSort ?? false,
    },
    objectLabel: {
      label: 'Labels',
      width: '15%',
      isSortable: false,
    },
    created_at: {
      label: 'Creation date',
      width: '15%',
      isSortable: true,
    },
    objectMarking: {
      label: 'Marking',
      isSortable: isRuntimeSort ?? false,
      width: '8%',
    },
  };
  return (
    <div style={{ height: '100%' }}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{ float: 'left', paddingBottom: 11 }}
      >
        {t('Related entities')}
      </Typography>
      <Security needs={security}>
        <ContainerAddStixCoreObjects
          containerId={container.id}
          containerStixCoreObjects={container.objects?.edges}
          paginationOptions={paginationOptions}
          simple={true}
          targetStixCoreObjectTypes={
            types ?? ['Stix-Domain-Object', 'Stix-Cyber-Observable']
          }
        />
      </Security>
      <div className="clearfix" />
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <QueryRenderer
          query={ContainerStixObjectsOrStixRelationshipsLinesQuery}
          variables={{
            id: container.id,
            count: 50,
          }}
          render={({
            props,
          }: {
            props: ContainerStixObjectsOrStixRelationshipsLinesQuery$data;
          }) => {
            if (props && props.container && props.container.objects) {
              return (
                <ContainerStixObjectsOrStixRelationshipsLines
                  container={props.container}
                  dataColumns={dataColumns}
                />
              );
            }
            return (
              <List>
                {Array.from(Array(10), (e, i) => (
                  <ContainerStixObjectOrStixRelationshipLineDummy
                    key={i}
                    dataColumns={dataColumns}
                  />
                ))}
              </List>
            );
          }}
        />
      </Paper>
    </div>
  );
};

const ContainerStixObjectsOrStixRelationships = createFragmentContainer(
  ContainerStixObjectsOrStixRelationshipsComponent,
  {
    container: graphql`
      fragment ContainerStixObjectsOrStixRelationships_container on Container {
        id
        createdBy {
          id
        }
        objects {
          edges {
            node {
              ... on BasicObject {
                id
              }
            }
          }
        }
        ...ContainerHeader_container
      }
    `,
  },
);

export default ContainerStixObjectsOrStixRelationships;
