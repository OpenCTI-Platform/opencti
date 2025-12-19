import React, { FunctionComponent, useContext } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import { QueryRenderer } from '../../../../relay/environment';
import ContainerStixObjectsOrStixRelationshipsLines, { ContainerStixObjectsOrStixRelationshipsLinesQuery } from './ContainerStixObjectsOrStixRelationshipsLines';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import ContainerAddStixCoreObjects from './ContainerAddStixCoreObjects';
import { ContainerStixObjectsOrStixRelationshipsLinesQuery$data } from './__generated__/ContainerStixObjectsOrStixRelationshipsLinesQuery.graphql';
import { ContainerStixObjectsOrStixRelationships_container$data } from './__generated__/ContainerStixObjectsOrStixRelationships_container.graphql';
import useAuth, { UserContext } from '../../../../utils/hooks/useAuth';
import useGranted, { KNOWLEDGE_KNPARTICIPATE, KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { ContainerStixObjectOrStixRelationshipLineDummy } from './ContainerStixObjectOrStixRelationshipLine';
import { Stack } from '@mui/material';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  paper: {
    margin: '-5px 0 0 0',
    padding: 0,
    borderRadius: 4,
  },
}));

interface ContainerStixObjectsOrStixRelationshipsComponentProps {
  title?: string;
  types?: string[];
  isSupportParticipation: boolean;
  container: ContainerStixObjectsOrStixRelationships_container$data;
  variant?: string;
  enableReferences: boolean;
}

const ContainerStixObjectsOrStixRelationshipsComponent: FunctionComponent<
  ContainerStixObjectsOrStixRelationshipsComponentProps
> = ({ container, isSupportParticipation = false, types, title, variant, enableReferences }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const userIsKnowledgeEditor = useGranted([KNOWLEDGE_KNUPDATE]);
  const { me } = useContext(UserContext);
  const security = [KNOWLEDGE_KNUPDATE];
  const isContainerOwner = userIsKnowledgeEditor || me?.individual_id === container.createdBy?.id;
  if (isSupportParticipation && isContainerOwner) {
    security.push(KNOWLEDGE_KNPARTICIPATE);
  }
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const paginationOptions = {
    id: container?.id ?? null,
    types: types ?? [],
    count: 10,
  };
  const dataColumns = {
    entity_type: {
      label: 'Type',
      width: '12%',
      isSortable: true,
    },
    name: {
      label: 'Name',
      width: '35%',
      isSortable: true,
    },
    createdBy: {
      label: 'Author',
      width: '12%',
      isSortable: isRuntimeSort,
    },
    objectLabel: {
      label: 'Labels',
      width: '12%',
      isSortable: false,
    },
    created_at: {
      label: 'Platform creation date',
      width: '12%',
      isSortable: true,
    },
    objectMarking: {
      label: 'Marking',
      isSortable: isRuntimeSort,
      width: '10%',
    },
  };
  const renderContent = () => {
    return (
      <QueryRenderer
        query={ContainerStixObjectsOrStixRelationshipsLinesQuery}
        variables={paginationOptions}
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
                paginationOptions={paginationOptions}
                enableReferences={enableReferences}
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
    );
  };
  return (
    <div style={{ height: '100%' }}>
      <Stack direction="row" alignItems="center" gap={1} sx={{ marginBottom: '8px' }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          sx={{ margin: 0 }}
        >
          {title ?? t_i18n('Related entities')}
        </Typography>
        {
          container && (
            <Security needs={security}>
              <ContainerAddStixCoreObjects
                containerId={container.id}
                containerStixCoreObjects={container.objects?.edges ?? []}
                paginationOptions={paginationOptions}
                simple={true}
                targetStixCoreObjectTypes={
                  types ?? ['Stix-Domain-Object', 'Stix-Cyber-Observable']
                }
                defaultCreatedBy={container.createdBy ?? null}
                defaultMarkingDefinitions={container.objectMarking ?? []}
                confidence={container.confidence}
                enableReferences={enableReferences}
              />
            </Security>
          )
        }
      </Stack>
      <div className="clearfix" />
      {variant !== 'noPaper' ? (
        <Paper classes={{ root: classes.paper }} className="paper-for-grid" variant="outlined">
          {renderContent()}
        </Paper>
      ) : (
        renderContent()
      )}
    </div>
  );
};

const ContainerStixObjectsOrStixRelationships = createFragmentContainer(
  ContainerStixObjectsOrStixRelationshipsComponent,
  {
    container: graphql`
      fragment ContainerStixObjectsOrStixRelationships_container on Container {
        id
        confidence
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        creators {
          id
          name
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
