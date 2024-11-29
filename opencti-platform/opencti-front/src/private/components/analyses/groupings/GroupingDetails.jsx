import React, { useState, useRef, useEffect } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import ListItem from '@mui/material/ListItem';
import { Link, useNavigate } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import { ExpandLessOutlined, ExpandMoreOutlined, OpenInNewOutlined } from '@mui/icons-material';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import StixRelationshipsHorizontalBars from '../../common/stix_relationships/StixRelationshipsHorizontalBars';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import { resolveLink } from '../../../../utils/Entity';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
    position: 'relative',
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
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
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
  itemIconDisabled: {
    marginRight: 0,
    color: theme.palette.grey[700],
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
});

const inlineStyles = {
  itemAuthor: {
    width: 80,
    minWidth: 80,
    maxWidth: 80,
    marginRight: 24,
    marginLeft: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  itemDate: {
    width: 80,
    minWidth: 80,
    maxWidth: 80,
    marginRight: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

const GroupingDetailsComponent = (props) => {
  const { t, fsd, classes, grouping } = props;
  const navigate = useNavigate();
  const [expanded, setExpanded] = useState(false);
  const [height, setHeight] = useState(0);
  const ref = useRef(null);
  useEffect(() => {
    setHeight(ref.current.clientHeight);
  });
  const expandable = grouping.relatedContainers.edges.length > 5;
  const relatedContainers = grouping.relatedContainers.edges
    .filter((relatedContainerEdge) => relatedContainerEdge.node.id !== grouping.id)
    .slice(0, expanded ? 200 : 5);

  const entitiesDistributionDataSelection = [
    {
      label: '',
      attribute: 'entity_type',
      date_attribute: 'first_seen',
      perspective: 'relationships',
      isTo: true,
      filters: {
        mode: 'and',
        filters: [
          {
            key: 'relationship_type',
            values: [
              'object',
            ],
            operator: 'eq',
            mode: 'or',
          },
        ],
        filterGroups: [],
      },
      dynamicFrom: emptyFilterGroup,
      dynamicTo: emptyFilterGroup,
    },
  ];

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Entity details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
          <Grid item xs={6} ref={ref}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Description')}
            </Typography>
            <ExpandableMarkdown source={grouping.description} limit={400} />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Context')}
            </Typography>
            <Chip classes={{ root: classes.chip }} label={grouping.context} />
          </Grid>
          <Grid item xs={6} style={{ minHeight: 200, maxHeight: height }}>
            <StixRelationshipsHorizontalBars
              isWidget={false}
              fromId={grouping.id}
              startDate={null}
              endDate={null}
              relationshipType="object"
              dataSelection={entitiesDistributionDataSelection}
              parameters={{ title: 'Entities distribution' }}
              variant="inEntity"
              isReadOnly={true}
            />
          </Grid>
        </Grid>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Correlated containers')}
          </Typography>
          <IconButton
            color="primary"
            aria-label="Go to correlation graph view"
            onClick={() => navigate(`/dashboard/analyses/groupings/${grouping.id}/knowledge/correlation`)}
            size="medium"
            style={{ marginBottom: 4 }}
          >
            <OpenInNewOutlined fontSize="small"/>
          </IconButton>
        </div>
        <List>
          {relatedContainers.length > 0
            ? relatedContainers.map((relatedContainerEdge) => {
              const relatedContainer = relatedContainerEdge.node;
              return (
                <ListItem
                  key={grouping.id}
                  dense={true}
                  button={true}
                  classes={{ root: classes.item }}
                  divider={true}
                  component={Link}
                  to={`${resolveLink(relatedContainer.entity_type)}/${relatedContainer.id}`}
                >
                  <ListItemIcon>
                    <ItemIcon type={relatedContainer.entity_type} />
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <div className={classes.itemText}>
                        {relatedContainer.name}
                      </div>
                  }
                  />
                  <div style={inlineStyles.itemAuthor}>
                    {relatedContainer.createdBy?.name ?? '-'}
                  </div>
                  <div style={inlineStyles.itemDate}>
                    {fsd(relatedContainer.created ?? relatedContainer.published)}
                  </div>
                  <div style={{ width: 110, paddingRight: 20 }}>
                    <ItemMarkings
                      variant="inList"
                      markingDefinitions={relatedContainer.objectMarking}
                      limit={1}
                    />
                  </div>
                </ListItem>
              );
            }) : '-'
          }
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

GroupingDetailsComponent.propTypes = {
  grouping: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const GroupingDetails = createFragmentContainer(GroupingDetailsComponent, {
  grouping: graphql`
    fragment GroupingDetails_grouping on Grouping {
      id
      context
      description
      relatedContainers(
        first: 10
        orderBy: published
        orderMode: desc
        types: ["Case", "Report", "Grouping"]
        viaTypes: ["Indicator", "Stix-Cyber-Observable"]
      ) {
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
    }
`,
});

export default R.compose(inject18n, withStyles(styles))(GroupingDetails);
