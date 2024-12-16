import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { NorthEastOutlined } from '@mui/icons-material';
import { VectorLink } from 'mdi-material-ui';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { graphql, useFragment } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import RelatedContainersDetails from '@components/common/containers/related_containers/RelatedContainersDetails';
import Drawer from '@components/common/drawer/Drawer';
import {
  RelatedContainersFragment_container_connection$data,
  RelatedContainersFragment_container_connection$key,
} from '@components/common/containers/related_containers/__generated__/RelatedContainersFragment_container_connection.graphql';
import { resolveLink } from '../../../../../utils/Entity';
import { useFormatter } from '../../../../../components/i18n';
import DataTableWithoutFragment from '../../../../../components/dataGrid/DataTableWithoutFragment';

export const RelatedContainersFragment = graphql`
  fragment RelatedContainersFragment_container_connection on ContainerConnection {
    edges {
      node {
        id
        entity_type
        objectMarking {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        creators {
          id
          name
        }
        status {
          id
          order
          template {
            name
            color
          }
        }
        workflowEnabled
        ... on Report {
          name
          modified
          description
          objectAssignee {
            entity_type
            id
            name
          }
        }
        ... on Grouping {
          name
          modified
          description
        }
        ... on CaseIncident {
          name
          modified
          description
          objectAssignee {
            entity_type
            id
            name
          }

        }
        ... on CaseRfi {
          name
          modified
          description
          objectAssignee {
            entity_type
            id
            name
          }

        }
        ... on CaseRft {
          name
          modified
          description
          objectAssignee {
            entity_type
            id
            name
          }

        }
      }
    }
    pageInfo {
      globalCount
    }
  }
`;

export type RelatedContainerNode = NonNullable<NonNullable<RelatedContainersFragment_container_connection$data['edges']>[number]>['node'];

interface RelatedContainersProps {
  relatedContainers: RelatedContainersFragment_container_connection$key | null | undefined;
  containerId: string;
  entityType: string;
}

const RelatedContainers: React.FC<RelatedContainersProps> = ({
  relatedContainers: relatedContainersKey,
  containerId,
  entityType,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [selectedContainer, setSelectedContainer] = useState<RelatedContainerNode | undefined>();
  const relatedContainers = useFragment(
    RelatedContainersFragment,
    relatedContainersKey,
  );
  const [ref, setRef] = useState<HTMLDivElement | undefined>();

  const containers = (relatedContainers?.edges ?? []).filter((edge) => edge?.node.id !== containerId).map((edge) => edge?.node);
  const containersGlobalCount = relatedContainers?.pageInfo?.globalCount ?? 0;

  const handleOpenDetails = (container?: RelatedContainerNode) => {
    if (!container) {
      return;
    }
    setSelectedContainer(container);
  };

  return (
    <div style={{
      marginTop: 20,
      flex: 1,
      display: 'flex',
      flexFlow: 'column',
    }}
    >
      <Typography variant="h3" gutterBottom={true} style={{}}>
        {t_i18n('Correlated containers')}
        <Tooltip title={t_i18n('Go to correlation graph view')} placement="top">
          <IconButton
            color="primary"
            component={Link}
            style={{ marginBottom: 4 }}
            to={`${resolveLink(entityType)}/${containerId}/knowledge/correlation`}
          >
            <VectorLink fontSize="small"/>
          </IconButton>
        </Tooltip>
      </Typography>
      <div style={{ height: '100%' }} ref={(r) => setRef(r ?? undefined)}>
        {containersGlobalCount > 0 ? (
          <DataTableWithoutFragment
            dataColumns={{
              entity_type: { percentWidth: 15 },
              name: { percentWidth: 40 },
              createdBy: { percentWidth: 15 },
              modified: { percentWidth: 15 },
              objectMarking: { percentWidth: 15 },
            }}
            data={containers}
            globalCount={containersGlobalCount}
            rootRef={ref}
            disableNavigation={true}
            storageKey={`related-containers-${entityType}-${containerId}`}
            hideHeaders={true}
            onLineClick={(row: RelatedContainerNode) => handleOpenDetails(row)}
          />) : (
            <div style={{
              display: 'flex',
              height: '100%',
              alignItems: 'center',
              justifyContent: 'center',
            }}
            >
              <span>
                {t_i18n('No correlated containers has been found.')}
              </span>
            </div>
        )}
      </div>
      <Drawer
        title={selectedContainer?.name ?? '-'}
        open={!!selectedContainer}
        onClose={() => setSelectedContainer(undefined)}
        header={
          <IconButton
            color="primary"
            aria-label="Go to container"
            onClick={() => navigate(`${resolveLink(selectedContainer?.entity_type)}/${selectedContainer?.id}`)}
            size="medium"
            style={{ position: 'absolute', right: 12 }}
          >
            <NorthEastOutlined/>
          </IconButton>
        }
      >
        {selectedContainer && (
          <RelatedContainersDetails
            containerId={containerId}
            relatedContainer={selectedContainer}
          />
        )}
      </Drawer>
    </div>
  );
};

export default RelatedContainers;
