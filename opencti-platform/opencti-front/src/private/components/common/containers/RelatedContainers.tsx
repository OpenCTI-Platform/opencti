import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { graphql, useFragment } from 'react-relay';
import { VectorLink } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/styles';
import { resolveLink } from '../../../../utils/Entity';
import { useFormatter } from '../../../../components/i18n';
import {
  RelatedContainersFragment_container_connection$key,
  RelatedContainersFragment_container_connection$data,
} from './__generated__/RelatedContainersFragment_container_connection.graphql';
import DataTableWithoutFragment from '../../../../components/dataGrid/DataTableWithoutFragment';
import type { Theme } from '../../../../components/Theme';

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
        ... on Report {
          name
          modified
        }
        ... on Grouping {
          name
          modified
        }
        ... on CaseIncident {
          name
          modified
        }
        ... on CaseRfi {
          name
          modified
        }
        ... on CaseRft {
          name
          modified
        }
      }
    }
    pageInfo {
      globalCount
    }
  }
`;

type RelatedContainerNode = NonNullable<NonNullable<RelatedContainersFragment_container_connection$data['edges']>[number]>['node'];

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
  const navigate = useNavigate();
  const relatedContainers = useFragment(
    RelatedContainersFragment,
    relatedContainersKey,
  );
  const [ref, setRef] = useState<HTMLDivElement | undefined>();

  const containers = (relatedContainers?.edges ?? []).filter((edge) => edge?.node.id !== containerId).map((edge) => edge?.node);
  const containersGlobalCount = relatedContainers?.pageInfo?.globalCount ?? 0;

  return (
    <div style={{
      marginTop: 10,
      flex: 1,
      display: 'flex',
      flexFlow: 'column',
    }}
    >
      <Typography variant="h3" gutterBottom={true}>
        {t_i18n('Correlated containers')}
        <Tooltip title={t_i18n('Go to correlation graph view')} placement="top">
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
            onLineClick={(row: RelatedContainerNode) => navigate(`${resolveLink(row?.entity_type)}/${row?.id}`)}
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
    </div>
  );
};

export default RelatedContainers;
