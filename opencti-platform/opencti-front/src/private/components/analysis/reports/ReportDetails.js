import React, { useState, useRef, useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { compose, head, pathOr } from 'ramda';
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
import {
  DescriptionOutlined,
  ExpandLessOutlined,
  ExpandMoreOutlined,
} from '@mui/icons-material';
import * as R from 'ramda';
import Button from '@mui/material/Button';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import EntityStixCoreRelationshipsHorizontalBars from '../../common/stix_core_relationships/EntityStixCoreRelationshipsHorizontalBars';
import ItemMarking from '../../../../components/ItemMarking';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
    position: 'relative',
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    borderRadius: '0',
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

const ReportDetailsComponent = (props) => {
  const { t, fldt, fsd, classes, report } = props;
  const [expanded, setExpanded] = useState(false);
  const [height, setHeight] = useState(0);
  const ref = useRef(null);
  useEffect(() => {
    setHeight(ref.current.clientHeight);
  });
  const expandable = report.relatedContainers.edges.length > 5;
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Entity details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
          <Grid item={true} xs={6} ref={ref}>
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
            {report.report_types?.map((reportType) => (
              <Chip
                key={reportType}
                classes={{ root: classes.chip }}
                label={reportType}
              />
            ))}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Publication date')}
            </Typography>
            {fldt(report.published)}
          </Grid>
          <Grid item={true} xs={6} style={{ maxHeight: height }}>
            <EntityStixCoreRelationshipsHorizontalBars
              title={t('Entities distribution')}
              variant="inEntity"
              stixCoreObjectId={report.id}
              toTypes={['Stix-Core-Object']}
              relationshipType="object"
              field="entity_type"
              seriesName={t('Number of entities')}
            />
          </Grid>
        </Grid>
        <Typography variant="h3" gutterBottom={true}>
          {t('Related reports')}
        </Typography>
        <List>
          {R.take(expanded ? 200 : 5, report.relatedContainers.edges)
            .filter(
              (relatedContainerEdge) => relatedContainerEdge.node.id !== report.id,
            )
            .map((relatedContainerEdge) => {
              const relatedContainer = relatedContainerEdge.node;
              const markingDefinition = head(
                pathOr([], ['objectMarking', 'edges'], relatedContainer),
              );
              return (
                <ListItem
                  key={report.id}
                  dense={true}
                  button={true}
                  classes={{ root: classes.item }}
                  divider={true}
                  component={Link}
                  to={`/dashboard/analysis/reports/${relatedContainer.id}`}
                >
                  <ListItemIcon>
                    <DescriptionOutlined color="primary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <div className={classes.itemText}>
                        {relatedContainer.name}
                      </div>
                    }
                  />
                  <div style={inlineStyles.itemAuthor}>
                    {pathOr('', ['createdBy', 'name'], relatedContainer)}
                  </div>
                  <div style={inlineStyles.itemDate}>
                    {fsd(relatedContainer.published)}
                  </div>
                  <div style={{ width: 110, paddingRight: 20 }}>
                    {markingDefinition && (
                      <ItemMarking
                        key={markingDefinition.node.id}
                        label={markingDefinition.node.definition}
                        variant="inList"
                      />
                    )}
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
                edges {
                  node {
                    definition
                  }
                }
              }
            }
          }
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ReportDetails);
