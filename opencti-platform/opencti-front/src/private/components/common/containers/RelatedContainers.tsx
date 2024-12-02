import React, { useState } from 'react';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Button from '@mui/material/Button';
import { ExpandLessOutlined, ExpandMoreOutlined, OpenInNewOutlined } from '@mui/icons-material';
import { Link, useNavigate } from 'react-router-dom';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import { resolveLink } from '../../../../utils/Entity';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { RelatedContainersFragment$key } from './__generated__/RelatedContainersFragment.graphql';

export const RelatedContainersFragment = graphql`
  fragment RelatedContainersFragment_containers_connection on ContainerConnection {
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
          published
        }
        ... on Grouping {
          name
          created
        }
        ... on CaseIncident {
          name
          created
        }
        ... on CaseRfi {
          name
          created
        }
        ... on CaseRft {
          name
          created
        }
      }
    }
  }
`;

interface RelatedContainersProps {
  relatedContainers: RelatedContainersFragment$key | null | undefined;
  containerId: string;
  entityType: string;
}

const RelatedContainers: React.FC<RelatedContainersProps> = ({
  relatedContainers: relatedContainersKey,
  containerId,
  entityType,
}) => {
  const { t_i18n, fsd } = useFormatter();
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const [expanded, setExpanded] = useState(false);
  const relatedContainers = useFragment(
    RelatedContainersFragment,
    relatedContainersKey,
  );

  const containersEdges = relatedContainers?.edges ?? [];
  const expandable = containersEdges.length > 5;
  const containers = containersEdges
    .filter((edge) => edge?.node.id !== containerId)
    .slice(0, expanded ? 200 : 5);

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Correlated containers')}
        </Typography>
        <IconButton
          color="primary"
          aria-label="Go to correlation graph view"
          onClick={() => navigate(`${resolveLink(entityType)}/${containerId}/knowledge/correlation`)}
          size="medium"
          style={{ marginBottom: 4 }}
        >
          <OpenInNewOutlined fontSize="small"/>
        </IconButton>
      </div>
      <List sx={{ marginBottom: 1 }}>
        {containers.length > 0 ? (
          containers.map((edge) => {
            const relatedContainer = edge?.node;
            return (
              <ListItem
                key={relatedContainer?.id}
                button
                divider
                component={Link}
                to={`${resolveLink(relatedContainer?.entity_type)}/${relatedContainer?.id}`}
                sx={{
                  '&': {
                    height: 50,
                    minHeight: 50,
                    maxHeight: 50,
                    paddingRight: 0,
                  },
                }}
              >
                <ListItemIcon>
                  <ItemIcon type={relatedContainer?.entity_type}/>
                </ListItemIcon>
                <ListItemText primary={
                  <div style={{
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    paddingRight: 10,
                  }}
                  >
                    {relatedContainer?.name}
                  </div>
                 }
                />
                <div style={{
                  width: 100,
                  minWidth: 100,
                  maxWidth: 100,
                  marginRight: 24,
                  marginLeft: 24,
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
                >{relatedContainer?.createdBy?.name ?? '-'}</div>
                <div style={{
                  width: 100,
                  minWidth: 100,
                  maxWidth: 100,
                  marginRight: 24,
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
                >{fsd(relatedContainer?.created ?? relatedContainer?.published)}</div>
                <div style={{
                  width: 110,
                  paddingRight: 20,
                }}
                >
                  <ItemMarkings
                    variant="inList"
                    markingDefinitions={relatedContainer?.objectMarking ?? []}
                    limit={1}
                  />
                </div>
              </ListItem>
            );
          })
        )
          : '-'}
      </List>
      {expandable && (
        <Button
          onClick={() => setExpanded(!expanded)}
          sx={{
            position: 'absolute',
            left: 0,
            bottom: 0,
            width: '100%',
            height: 25,
            color: theme.palette.primary.main,
            backgroundColor:
              theme.palette.mode === 'dark'
                ? 'rgba(255, 255, 255, .1)'
                : 'rgba(0, 0, 0, .1)',
            borderTopLeftRadius: 0,
            borderTopRightRadius: 0,
            '&:hover': {
              backgroundColor:
                theme.palette.mode === 'dark'
                  ? 'rgba(255, 255, 255, .2)'
                  : 'rgba(0, 0, 0, .2)',
            },
          }}
          variant="contained"
        >
          {expanded ? <ExpandLessOutlined/> : <ExpandMoreOutlined/>}
        </Button>
      )}
    </div>
  );
};

export default RelatedContainers;
