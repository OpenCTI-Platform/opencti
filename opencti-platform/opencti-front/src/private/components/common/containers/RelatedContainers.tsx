import React, { useState } from 'react';
import { OpenInNewOutlined } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { graphql, useFragment } from 'react-relay';
import { resolveLink } from '../../../../utils/Entity';
import { useFormatter } from '../../../../components/i18n';
import {
  RelatedContainersFragment_container_connection$key,
  RelatedContainersFragment_container_connection$data,
} from './__generated__/RelatedContainersFragment_container_connection.graphql';
import DataTableWithoutFragment from '../../../../components/dataGrid/DataTableWithoutFragment';

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
  const navigate = useNavigate();
  const relatedContainers = useFragment(
    RelatedContainersFragment,
    relatedContainersKey,
  );
  const [ref, setRef] = useState<HTMLDivElement | undefined>();

  const containers = (relatedContainers?.edges ?? []).filter((edge) => edge?.node.id !== containerId).map((edge) => edge?.node);
  const containersGlobalCount = relatedContainers?.pageInfo?.globalCount ?? 0;

  return (
    <div style={{ marginTop: 20, height: 300 }} ref={(r) => setRef(r ?? undefined)}>
      <Typography variant="h3" gutterBottom={true} style={{ }}>
        {t_i18n('Correlated containers')}
        <IconButton
          color="primary"
          aria-label="Go to correlation graph view"
          onClick={() => navigate(`${resolveLink(entityType)}/${containerId}/knowledge/correlation`)}
          size="medium"
          style={{ marginBottom: 4 }}
        >
          <OpenInNewOutlined fontSize="small"/>
        </IconButton>
      </Typography>
      <div className="clearfix"/>
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
    </div>
  );
};

export default RelatedContainers;
