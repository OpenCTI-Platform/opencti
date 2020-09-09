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
import { AccountBalanceOutlined } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import { QueryRenderer } from '../../../../relay/environment';

const styles = (theme) => ({
  paper: {
    height: '100%',
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

const sectorTargetedOrganizationsQuery = graphql`
  query SectorTargetedOrganizationsQuery($id: String!) {
    sector(id: $id) {
      id
      name
      targetedOrganizations {
        edges {
          node {
            id
            start_time
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
                  definition
                  x_opencti_color
                }
              }
            }
            from {
              ... on BasicObject {
                id
                entity_type
              }
            }
            to {
              ... on BasicObject {
                id
                entity_type
              }
            }
          }
        }
      }
    }
  }
`;

class SectorTargetedOrganizations extends Component {
  render() {
    const {
      t, nsd, classes, sectorId,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Last targeted organizations in this sector')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={sectorTargetedOrganizationsQuery}
            variables={{ id: sectorId }}
            render={({ props }) => {
              if (props && props.sector) {
                if (props.sector.targetedOrganizations.edges.length > 0) {
                  return (
                    <List>
                      {props.sector.targetedOrganizations.edges.map(
                        (relationedge) => {
                          const relation = relationedge.node;
                          const markingDefinition = head(
                            pathOr([], ['objectMarking', 'edges'], relation),
                          );
                          return (
                            <ListItem
                              key={relation.id}
                              dense={true}
                              button={true}
                              classes={{ root: classes.item }}
                              divider={true}
                              component={Link}
                              to={`/dashboard/entities/organizations/${relation.to.id}/knowledge/relations/${relation.id}`}
                            >
                              <ListItemIcon>
                                <AccountBalanceOutlined color="primary" />
                              </ListItemIcon>
                              <ListItemText
                                primary={
                                  <div className={classes.itemText}>test</div>
                                }
                              />
                              <div style={inlineStyles.itemAuthor}>
                                {pathOr('', ['createdBy', 'name'], relation)}
                              </div>
                              <div style={inlineStyles.itemDate}>
                                {nsd(relation.start_time)}
                              </div>
                              <div style={{ width: 110, paddingRight: 20 }}>
                                {markingDefinition ? (
                                  <ItemMarking
                                    key={markingDefinition.node.id}
                                    label={markingDefinition.node.definition}
                                    color={
                                      markingDefinition.node.x_opencti_color
                                    }
                                    variant="inList"
                                  />
                                ) : (
                                  ''
                                )}
                              </div>
                            </ListItem>
                          );
                        },
                      )}
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
                      {t('No entities of this type has been found.')}
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
                      <ListItemIcon
                        classes={{ root: classes.itemIconDisabled }}
                      >
                        <AccountBalanceOutlined />
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

SectorTargetedOrganizations.propTypes = {
  sectorId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(SectorTargetedOrganizations);
