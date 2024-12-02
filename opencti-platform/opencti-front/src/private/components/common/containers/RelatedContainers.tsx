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
import { CaseRfiDetails_case$data } from '@components/cases/case_rfis/__generated__/CaseRfiDetails_case.graphql';
import { CaseRftDetails_case$data } from '@components/cases/case_rfts/__generated__/CaseRftDetails_case.graphql';
import { CaseIncidentDetails_case$data } from '@components/cases/case_incidents/__generated__/CaseIncidentDetails_case.graphql';
import { ReportDetails_report$data } from '@components/analyses/reports/__generated__/ReportDetails_report.graphql';
import { GroupingDetails_grouping$data } from '@components/analyses/groupings/__generated__/GroupingDetails_grouping.graphql';
import { resolveLink } from '../../../../utils/Entity';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

interface RelatedContainersProps {
  relatedContainers: ReportDetails_report$data['relatedContainers']
  | GroupingDetails_grouping$data['relatedContainers']
  | CaseIncidentDetails_case$data['relatedContainers']
  | CaseRftDetails_case$data['relatedContainers']
  | CaseRfiDetails_case$data['relatedContainers']
  containerId: string;
  entityType: string;
}

const RelatedContainers: React.FC<RelatedContainersProps> = ({
  relatedContainers,
  containerId,
  entityType,
}) => {
  const { t_i18n, fsd } = useFormatter();
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const [expanded, setExpanded] = useState(false);

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
      <List>
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
