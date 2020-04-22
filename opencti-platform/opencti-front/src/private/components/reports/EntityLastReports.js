import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { compose, pathOr, head } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { DescriptionOutlined } from '@material-ui/icons';
import inject18n from '../../../components/i18n';
import ItemMarking from '../../../components/ItemMarking';
import { QueryRenderer } from '../../../relay/environment';

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
    color: '#ffffff',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  itemDate: {
    width: 80,
    minWidth: 80,
    maxWidth: 80,
    marginRight: 24,
    color: '#ffffff',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

const entityLastReportsQuery = graphql`
  query EntityLastReportsQuery(
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
          createdByRef {
            node {
              name
            }
          }
          markingDefinitions {
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

class EntityLastReports extends Component {
  render() {
    const {
      t,
      nsd,
      classes,
      entityId,
      stixObservableId,
      authorId,
    } = this.props;
    const filters = [];
    if (authorId) filters.push({ key: 'createdBy', values: [authorId] });
    if (entityId) filters.push({ key: 'knowledgeContains', values: [entityId] });
    if (stixObservableId) filters.push({ key: 'observablesContains', values: [stixObservableId] });
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {authorId
            ? t('Last reports wrote by the entity')
            : t('Last reports about the entity')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={entityLastReportsQuery}
            variables={{
              first: 8,
              orderBy: 'published',
              orderMode: 'desc',
              filters,
            }}
            render={({ props }) => {
              if (props && props.reports) {
                return (
                  <List>
                    {props.reports.edges.map((reportEdge) => {
                      const report = reportEdge.node;
                      const markingDefinition = head(
                        pathOr([], ['markingDefinitions', 'edges'], report),
                      );
                      return (
                        <ListItem
                          key={report.id}
                          dense={true}
                          button={true}
                          classes={{ root: classes.item }}
                          divider={true}
                          component={Link}
                          to={`/dashboard/reports/all/${report.id}`}
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
                            {pathOr(
                              '',
                              ['createdByRef', 'node', 'name'],
                              report,
                            )}
                          </div>
                          <div style={inlineStyles.itemDate}>
                            {nsd(report.published)}
                          </div>
                          <div style={{ width: 110, paddingRight: 20 }}>
                            {markingDefinition ? (
                              <ItemMarking
                                key={markingDefinition.node.id}
                                label={markingDefinition.node.definition}
                                variant="inList"
                              />
                            ) : (
                              ''
                            )}
                          </div>
                        </ListItem>
                      );
                    })}
                  </List>
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
                      <ListItemIcon
                        classes={{ root: classes.itemIconDisabled }}
                      >
                        <DescriptionOutlined />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <span className="fakeItem" style={{ width: '80%' }} />
                        }
                        secondary={
                          <span className="fakeItem" style={{ width: '90%' }} />
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

EntityLastReports.propTypes = {
  entityId: PropTypes.string,
  stixObservableId: PropTypes.string,
  authorId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(EntityLastReports);
