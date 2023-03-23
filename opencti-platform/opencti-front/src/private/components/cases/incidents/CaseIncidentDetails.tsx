import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import * as R from 'ramda';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Button from '@mui/material/Button';
import { ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import Chip from '@mui/material/Chip';
import ItemIcon from '../../../../components/ItemIcon';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemMarkings from '../../../../components/ItemMarkings';
import { Theme } from '../../../../components/Theme';
import {
  CaseIncidentDetails_case$data,
  CaseIncidentDetails_case$key,
} from './__generated__/CaseIncidentDetails_case.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  item: {
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  itemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
  itemIconDisabled: {
    marginRight: 0,
    color: theme.palette.grey ? theme.palette.grey[700] : undefined,
  },
  buttonExpand: {
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
  },
  itemAuthor: {
    width: 120,
    minWidth: 120,
    maxWidth: 120,
    marginRight: 24,
    marginLeft: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  itemDate: {
    width: 120,
    minWidth: 120,
    maxWidth: 120,
    marginRight: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  itemMarking: {
    width: 110,
    paddingRight: 20,
  },
}));

const CaseIncidentDetailsFragment = graphql`
  fragment CaseIncidentDetails_case on CaseIncident {
    id
    name
    description
    priority
    severity
    created
    modified
    created_at
    response_types
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
    name
    x_opencti_stix_ids
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    relatedContainers(
      first: 10
      orderBy: created
      orderMode: desc
      types: ["Case-Incident"]
      viaTypes: ["Indicator", "Stix-Cyber-Observable"]
    ) {
      edges {
        node {
          id
          entity_type
          ... on Case {
            name
            description
            created
            createdBy {
              ... on Identity {
                id
                name
                entity_type
              }
            }
            objectMarking {
              edges {
                node {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
              }
            }
          }
        }
      }
    }
  }
`;

interface CaseIncidentDetailsProps {
  caseIncidentData: CaseIncidentDetails_case$key;
}

const CaseIncidentDetails: FunctionComponent<CaseIncidentDetailsProps> = ({
  caseIncidentData,
}) => {
  const { t, fsd } = useFormatter();
  const classes = useStyles();
  const [expanded, setExpanded] = useState(false);
  const data: CaseIncidentDetails_case$data = useFragment(
    CaseIncidentDetailsFragment,
    caseIncidentData,
  );
  const expandable = (data.relatedContainers?.edges ?? []).length > 5;
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Priority')}
            </Typography>
            <ItemOpenVocab
              key="type"
              small={true}
              type="case_priority_ov"
              value={data.priority}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Severity')}
            </Typography>
            <ItemOpenVocab
              key="type"
              small={true}
              type="case_severity_ov"
              value={data.severity}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Response type')}
            </Typography>
            {(data.response_types ?? []).map((responseType) => (
                <Chip
                  key={responseType}
                  classes={{ root: classes.chip }}
                  label={responseType}
                />
            ))}
          </Grid>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Description')}
            </Typography>
            {data.description && (
              <ExpandableMarkdown source={data.description} limit={300} />
            )}
          </Grid>
        </Grid>
        <Typography variant="h3" gutterBottom={true}>
          {t('Related cases')}
        </Typography>
        <List>
          {R.take(expanded ? 200 : 5, data.relatedContainers?.edges ?? [])
            .filter(
              (relatedContainerEdge) => relatedContainerEdge?.node?.id !== data.id,
            )
            .map((relatedContainerEdge) => {
              const relatedContainer = relatedContainerEdge?.node;
              return (
                <ListItem
                  key={data.id}
                  dense={true}
                  classes={{ root: classes.item }}
                  divider={true}
                  component={Link}
                  to={`/dashboard/cases/incidents/${relatedContainer?.id}`}
                >
                  <ListItemIcon>
                    <ItemIcon type={relatedContainer?.entity_type} />
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <div className={classes.itemText}>
                        {relatedContainer?.name}
                      </div>
                    }
                  />
                  <div className={classes.itemAuthor}>
                    {R.pathOr('', ['createdBy', 'name'], relatedContainer)}
                  </div>
                  <div className={classes.itemDate}>
                    {fsd(relatedContainer?.created)}
                  </div>
                  <div className={classes.itemMarking}>
                    <ItemMarkings
                      variant="inList"
                      markingDefinitionsEdges={
                        relatedContainer?.objectMarking?.edges ?? []
                      }
                      limit={1}
                    />
                  </div>
                </ListItem>
              );
            })}
        </List>
        {expandable && (
          <Button
            variant="contained"
            size="small"
            onClick={() => setExpanded(!expanded)}
            classes={{ root: classes.buttonExpand }}
          >
            {expanded ? (
              <ExpandLessOutlined fontSize="small" />
            ) : (
              <ExpandMoreOutlined fontSize="small" />
            )}
          </Button>
        )}
      </Paper>
    </div>
  );
};
export default CaseIncidentDetails;
