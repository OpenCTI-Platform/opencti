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
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import { ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import Button from '@mui/material/Button';
import StixRelationshipsHorizontalBars from '../../common/stix_relationships/StixRelationshipsHorizontalBars';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: theme.spacing(2),
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
});

const ReportDetailsComponent = (props) => {
  const { t, fldt, fsd, classes, report } = props;
  const [expanded, setExpanded] = useState(false);
  const [height, setHeight] = useState(0);
  const ref = useRef(null);
  useEffect(() => {
    setHeight(ref.current.clientHeight);
  });
  const expandable = report.relatedContainers.edges.length > 5;
  const relatedContainers = R.take(
    expanded ? 200 : 5,
    report.relatedContainers.edges,
  ).filter(
    (relatedContainerEdge) => relatedContainerEdge.node.id !== report.id,
  );

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
    <div style={{ height: '100%' }} data-testid='report-overview'>
      <Typography variant="h4" gutterBottom={true}>
        {t('Entity details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
          <Grid item xs={6} ref={ref}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Description')}
            </Typography>
            <ExpandableMarkdown source={report.description} limit={400} />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Report types')}
            </Typography>
            <FieldOrEmpty source={report.report_types}>
              {report.report_types?.map((reportType) => (
                <Chip
                  key={reportType}
                  classes={{ root: classes.chip }}
                  label={reportType}
                />
              ))}
            </FieldOrEmpty>
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Publication date')}
            </Typography>
            {fldt(report.published)}
          </Grid>
          <Grid
            item
            xs={6}
            style={{ minHeight: 200, maxHeight: height }}
          >
            <StixRelationshipsHorizontalBars
              isWidget={false}
              fromId={report.id}
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
        <Typography variant="h3" gutterBottom={true}>
          {t('Correlated reports')}
        </Typography>
        <List classes={{ root: classes.relatedContainers }}>
          {relatedContainers.length > 0
            ? relatedContainers.map((relatedContainerEdge) => {
              const relatedContainer = relatedContainerEdge.node;
              return (
                <ListItem
                  key={report.id}
                  dense={true}
                  button={true}
                  classes={{ root: classes.item }}
                  divider={true}
                  component={Link}
                  to={`/dashboard/analyses/reports/${relatedContainer.id}`}
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
                  <div className={classes.itemAuthor}>
                    {R.pathOr('', ['createdBy', 'name'], relatedContainer)}
                  </div>
                  <div className={classes.itemDate}>
                    {fsd(relatedContainer.published)}
                  </div>
                  <div className={classes.itemMarking}>
                    <ItemMarkings
                      variant="inList"
                      markingDefinitions={relatedContainer.objectMarking}
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

ReportDetailsComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ReportDetails = createFragmentContainer(ReportDetailsComponent, {
  report: graphql`
    fragment ReportDetails_report on Report {
      id
      published
      report_types
      description
      relatedContainers(
        first: 10
        orderBy: published
        orderMode: desc
        types: ["Report"]
        viaTypes: ["Indicator", "Stix-Cyber-Observable"]
      ) {
        edges {
          node {
            id
            entity_type
            ... on Report {
              name
              description
              published
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
  `,
});

export default R.compose(inject18n, withStyles(styles))(ReportDetails);
