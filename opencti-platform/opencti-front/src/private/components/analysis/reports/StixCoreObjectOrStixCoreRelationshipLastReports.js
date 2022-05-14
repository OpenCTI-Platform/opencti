import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { compose, pathOr, head } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { DescriptionOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import { QueryRenderer } from '../../../../relay/environment';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
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
    color: theme.palette.grey[700],
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

const stixCoreObjectOrStixCoreRelationshipLastReportsQuery = graphql`
  query StixCoreObjectOrStixCoreRelationshipLastReportsQuery(
    $first: Int
    $orderBy: ReportsOrdering
    $orderMode: OrderingMode
    $filters: [ReportsFiltering]
  ) {
    reports(
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
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
`;

class StixCoreObjectOrStixCoreRelationshipLastReports extends Component {
  render() {
    const {
      t,
      fsd,
      classes,
      stixCoreObjectOrStixCoreRelationshipId,
      authorId,
    } = this.props;
    const filters = [];
    if (authorId) filters.push({ key: 'createdBy', values: [authorId] });
    if (stixCoreObjectOrStixCoreRelationshipId) {
      filters.push({
        key: 'objectContains',
        values: [stixCoreObjectOrStixCoreRelationshipId],
      });
    }
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {authorId
            ? t('Latest reports written by this entity')
            : t('Latest reports about this entity')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <QueryRenderer
            query={stixCoreObjectOrStixCoreRelationshipLastReportsQuery}
            variables={{
              first: 8,
              orderBy: 'published',
              orderMode: 'desc',
              filters,
            }}
            render={({ props }) => {
              if (props && props.reports) {
                if (props.reports.edges.length > 0) {
                  return (
                    <List>
                      {props.reports.edges.map((reportEdge) => {
                        const report = reportEdge.node;
                        const markingDefinition = head(
                          pathOr([], ['objectMarking', 'edges'], report),
                        );
                        return (
                          <ListItem
                            key={report.id}
                            dense={true}
                            button={true}
                            classes={{ root: classes.item }}
                            divider={true}
                            component={Link}
                            to={`/dashboard/analysis/reports/${report.id}`}
                          >
                            <ListItemIcon>
                              <DescriptionOutlined color="primary" />
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <div className={classes.itemText}>
                                  {report.name}
                                </div>
                              }
                            />
                            <div style={inlineStyles.itemAuthor}>
                              {pathOr('', ['createdBy', 'name'], report)}
                            </div>
                            <div style={inlineStyles.itemDate}>
                              {fsd(report.published)}
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
                  );
                }
                return (
                  <div
                    style={{
                      display: 'table',
                      height: '100%',
                      width: '100%',
                      paddingTop: 15,
                      paddingBottom: 15,
                    }}
                  >
                    <span
                      style={{
                        display: 'table-cell',
                        verticalAlign: 'middle',
                        textAlign: 'center',
                      }}
                    >
                      {t('No reports about this entity.')}
                    </span>
                  </div>
                );
              }
              return (
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem
                      key={i}
                      dense={true}
                      divider={true}
                      button={false}
                    >
                      <ListItemIcon classes={{ root: classes.itemIcon }}>
                        <Skeleton
                          animation="wave"
                          variant="circular"
                          width={30}
                          height={30}
                        />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Skeleton
                            animation="wave"
                            variant="rectangular"
                            width="90%"
                            height={15}
                            style={{ marginBottom: 10 }}
                          />
                        }
                        secondary={
                          <Skeleton
                            animation="wave"
                            variant="rectangular"
                            width="90%"
                            height={15}
                          />
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              );
            }}
          />
        </Paper>
      </div>
    );
  }
}

StixCoreObjectOrStixCoreRelationshipLastReports.propTypes = {
  stixCoreObjectOrStixCoreRelationshipId: PropTypes.string,
  authorId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectOrStixCoreRelationshipLastReports);
