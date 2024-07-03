import { ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import type { Theme } from '../../../../components/Theme';
import { CaseRfiDetails_case$key } from './__generated__/CaseRfiDetails_case.graphql';
import { resolveLink } from '../../../../utils/Entity';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 4,
    position: 'relative',
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    borderRadius: 4,
    margin: '0 5px 5px 0',
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
  relatedContainers: {
    paddingTop: 0,
  },
}));

const CaseRfiDetailsFragment = graphql`
  fragment CaseRfiDetails_case on CaseRfi {
    id
    name
    description
    created
    modified
    created_at
    information_types
    severity
    priority
    objectLabel {
      id
      value
      color
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
      types: ["Case"]
      viaTypes: ["Indicator", "Stix-Cyber-Observable"]
    ) {
      edges {
        node {
          id
          entity_type
            ... on CaseIncident {
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
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
            ... on CaseRfi {
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
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
            ... on CaseRft {
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
`;

interface CaseRfiDetailsProps {
  caseRfiData: CaseRfiDetails_case$key;
}

const CaseRfiDetails: FunctionComponent<CaseRfiDetailsProps> = ({
  caseRfiData,
}) => {
  const { t_i18n, fsd } = useFormatter();
  const classes = useStyles();
  const [expanded, setExpanded] = useState(false);
  const data = useFragment(CaseRfiDetailsFragment, caseRfiData);
  const expandable = (data.relatedContainers?.edges ?? []).length > 5;
  const informationTypes = data.information_types ?? [];
  const relatedContainers = R.take(
    expanded ? 200 : 5,
    data.relatedContainers?.edges ?? [],
  ).filter(
    (relatedContainerEdge) => relatedContainerEdge?.node?.id !== data.id,
  );
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Information type')}
            </Typography>
            {informationTypes.length > 0
              ? (data.information_types ?? []).map((informationType) => (
                <Chip
                  key={informationType}
                  classes={{ root: classes.chip }}
                  label={informationType}
                />
              ))
              : '-'}
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Priority')}
            </Typography>
            <ItemOpenVocab
              key="type"
              small={true}
              type="case_priority_ov"
              value={data.priority}
              displayMode="chip"
            />
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Severity')}
            </Typography>
            <ItemOpenVocab
              key="type"
              small={true}
              type="case_severity_ov"
              value={data.severity}
              displayMode="chip"
            />
          </Grid>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            {data.description ? (
              <ExpandableMarkdown source={data.description} limit={300} />
            ) : (
              '-'
            )}
          </Grid>
        </Grid>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Correlated cases')}
        </Typography>
        <List classes={{ root: classes.relatedContainers }}>
          {relatedContainers.length > 0
            ? relatedContainers.map((relatedContainerEdge) => {
              const relatedContainer = relatedContainerEdge?.node;
              return (
                <ListItem
                  key={data.id}
                  dense={true}
                  button={true}
                  classes={{ root: classes.item }}
                  divider={true}
                  component={Link}
                  to={`${resolveLink(relatedContainer?.entity_type)}/${relatedContainer?.id}`}
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
                      markingDefinitions={
                          relatedContainer?.objectMarking ?? []
                        }
                      limit={1}
                    />
                  </div>
                </ListItem>
              );
            })
            : '-'}
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
export default CaseRfiDetails;
