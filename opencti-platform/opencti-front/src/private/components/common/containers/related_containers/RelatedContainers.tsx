import React, { useMemo, useState, Suspense } from 'react';
import { Link } from 'react-router-dom';
import { NorthEastOutlined, LoupeOutlined } from '@mui/icons-material';
import { VectorLink } from 'mdi-material-ui';
import IconButton from '@common/button/IconButton';
import Typography from '@mui/material/Typography';
import { graphql, useFragment } from 'react-relay';
import Tooltip from '@mui/material/Tooltip';
import RelatedContainersDetails from '@components/common/containers/related_containers/RelatedContainersDetails';
import Drawer from '@components/common/drawer/Drawer';
import {
  RelatedContainersFragment_container_connection$data,
  RelatedContainersFragment_container_connection$key,
} from '@components/common/containers/related_containers/__generated__/RelatedContainersFragment_container_connection.graphql';
import { useTheme } from '@mui/styles';
import Loader from 'src/components/Loader';
import type { Theme } from '../../../../../components/Theme';
import { resolveLink } from '../../../../../utils/Entity';
import { useFormatter } from '../../../../../components/i18n';
import DataTableWithoutFragment from '../../../../../components/dataGrid/DataTableWithoutFragment';
import { DataTableVariant } from '../../../../../components/dataGrid/dataTableTypes';

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
  const theme = useTheme<Theme>();
  const [selectedContainer, setSelectedContainer] = useState<RelatedContainerNode | undefined>();
  const relatedContainers = useFragment(
    RelatedContainersFragment,
    relatedContainersKey,
  );
  const [ref, setRef] = useState<HTMLDivElement | undefined>();

  const containers = (relatedContainers?.edges ?? []).filter((edge) => edge?.node.id !== containerId).map((edge) => edge?.node);
  const containersGlobalCount = containers.length ?? 0;

  const handleOpenDetails = (container?: RelatedContainerNode) => {
    if (!container) {
      return;
    }
    setSelectedContainer(container);
  };

  // Data table min height, setting 50px for empty containers, 50px per container up to 3, and capping at 150px.
  const calcMinHeight = useMemo(() => Math.max(Math.min(containersGlobalCount * 50, 150), 50), [containersGlobalCount]);

  return (
    <div style={{
      marginTop: 20,
      flex: 1,
      display: 'flex',
      flexFlow: 'column',
    }}
    >
      <Typography variant="h3" gutterBottom={true}>
        {t_i18n('Correlated containers')}
        <Tooltip title={t_i18n('Display the correlation graph')} placement="top">
          <IconButton
            color="primary"
            component={Link}
            style={{ marginBottom: theme.spacing(0.5) }}
            to={`${resolveLink(entityType)}/${containerId}/knowledge/correlation`}
          >
            <VectorLink fontSize="small" />
          </IconButton>
        </Tooltip>
      </Typography>
      <div style={{ height: '100%', minHeight: calcMinHeight }} ref={(r) => setRef(r ?? undefined)}>
        {containersGlobalCount > 0 ? (
          <DataTableWithoutFragment
            dataColumns={{
              entity_type: { percentWidth: 20 },
              name: { percentWidth: 20 },
              createdBy: { percentWidth: 20 },
              modified: { percentWidth: 20 },
              objectMarking: { percentWidth: 20 },
            }}
            data={containers}
            globalCount={containersGlobalCount}
            rootRef={ref}
            storageKey={`related-containers-${entityType}-${containerId}`}
            hideHeaders
            variant={DataTableVariant.inline}
            actions={(row) => (
              <div>
                <Tooltip title={t_i18n('Open the correlation details')} placement="top">
                  <IconButton
                    color="primary"
                    aria-haspopup="true"
                    style={{ marginTop: 3 }}
                    onClick={(event) => {
                      event.stopPropagation();
                      event.preventDefault();
                      handleOpenDetails(row);
                    }}
                  >
                    <LoupeOutlined fontSize="small" />
                  </IconButton>
                </Tooltip>
              </div>
            )}
          />
        ) : (
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
        header={(
          <Tooltip title={t_i18n('Go to container')}>
            <IconButton
              color="primary"
              component={Link}
              to={`${resolveLink(selectedContainer?.entity_type)}/${selectedContainer?.id}`}
              style={{ position: 'absolute', right: 12 }}
            >
              <NorthEastOutlined />
            </IconButton>
          </Tooltip>
        )}
      >
        <>
          {selectedContainer && (
            <Suspense fallback={<Loader />}>
              <RelatedContainersDetails
                containerId={containerId}
                relatedContainer={selectedContainer}
              />
            </Suspense>
          )}
        </>
      </Drawer>
    </div>
  );
};

export default RelatedContainers;
