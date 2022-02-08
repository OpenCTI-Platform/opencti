import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Skeleton from '@material-ui/lab/Skeleton';
import ListItemText from '@material-ui/core/ListItemText';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import Paper from '@material-ui/core/Paper';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR } from 'react-relay';
import QueryRendererDarkLight from '../../../../../relay/environmentDarkLight';
import { QueryRenderer } from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import ListLines from '../../../../../components/list_lines/ListLines';
import RemediationEntitiesLines from './RemediationEntitiesLines';
import StixCoreRelationshipCreationFromEntity from '../../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../../utils/Security';
import AddRemediation from './AddRemediation';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: 0,
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
  bodyItem: {
    height: 35,
    fontSize: 13,
    paddingLeft: 24,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    display: 'flex',
    justifyContent: 'left',
    alignItems: 'center',
  },
  ListItem: {
    width: '100%',
    display: 'flex',
    justifyContent: 'space-between',
  },
});

const remediationEntitiesQuery = graphql`
  query RemediationEntitiesQuery($id: ID!) {
    risk(id: $id) {
      id
      created
      modified
      remediations {
        id
        name                # Title
        description         # Description
        created             # Created
        modified            # Last Modified
        lifecycle           # Lifecycle
        response_type       # Response Type
        origins{
          id
          origin_actors {
            actor_type
            actor {
              ... on Component {
                id
                component_type
                name          # Source
              }
              ... on OscalParty {
              id
              party_type
              name            # Source
              }
            }
          }
        }
        tasks {             # only necessary if Start/End date is supported in UI
          edges {
            node {
              timing {
                ... on DateRangeTiming {
                  start_date
                  end_date
                }
              }
            }
          }
        }
      }
    }
  }
`;

class RemediationEntities extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: null,
      orderAsc: false,
      searchTerm: '',
      view: 'lines',
      relationReversed: false,
    };
  }

  handleReverseRelation() {
    this.setState({ relationReversed: !this.state.relationReversed });
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  renderLines(paginationOptions) {
    const { sortBy, orderAsc } = this.state;
    const { entityId, classes, t } = this.props;
    const dataColumns = {
      relationship_type: {
        label: 'Title',
        width: '15%',
        isSortable: true,
      },
      entity_type: {
        label: 'Response type',
        width: '15%',
        isSortable: false,
      },
      name: {
        label: 'Lifecycle',
        width: '15%',
        isSortable: false,
      },
      start_time: {
        label: 'Decision Maker',
        width: '15%',
        isSortable: true,
      },
      stop_time: {
        label: 'Start Date',
        width: '15%',
        isSortable: true,
      },
      confidence: {
        label: 'End Date',
        width: '12%',
        isSortable: true,
      },
      source: {
        label: 'Source',
        width: '12%',
        isSortable: true,
      },
    };
    return (
      <>
        {/* // <ListLines
      //   sortBy={sortBy}
      //   orderAsc={orderAsc}
      //   dataColumns={dataColumns}
      //   handleSort={this.handleSort.bind(this)}
      //   // handleSearch={this.handleSearch.bind(this)}
      //   displayImport={true}
      //   secondaryAction={true}
      //   searchVariant="inDrawer2"
      // > */}
        {/* <QueryRenderer */}
        <QR
          environment={QueryRendererDarkLight}
          query={remediationEntitiesQuery}
          variables={{ id: entityId }}
          render={({ props }) => {
            console.log('RemediationEntitiesData', props);
            if (props) {
              return (
                <RemediationEntitiesLines
                  data={props}
                  paginationOptions={paginationOptions}
                  dataColumns={dataColumns}
                  initialLoading={props === null}
                  displayRelation={true}
                  entityId={entityId}
                />
              );
            }
            return (
              <div style={{ height: '100%' }}>
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem
                      key={i}
                      dense={true}
                      divider={true}
                      button={false}
                    >
                      <ListItemText
                        primary={
                          <div className={ classes.ListItem }>
                            <div
                              className={classes.bodyItem}
                            >
                              <Skeleton
                                animation="wave"
                                variant="rect"
                                width={140}
                                height="100%"
                              />
                            </div>
                            <div
                              className={classes.bodyItem}
                            >
                              <Skeleton
                                animation="wave"
                                variant="rect"
                                width={140}
                                height="100%"
                              />
                            </div>
                            <div
                              className={classes.bodyItem}
                            >
                              <Skeleton
                                animation="wave"
                                variant="rect"
                                width={140}
                                height="100%"
                              />
                            </div>
                            <div
                              className={classes.bodyItem}
                            >
                              <Skeleton
                                animation="wave"
                                variant="rect"
                                width={140}
                                height='100%'
                              />
                            </div>
                            <div
                              className={classes.bodyItem}
                            >
                              <Skeleton
                                animation="wave"
                                variant="rect"
                                width={140}
                                height='100%'
                              />
                            </div>
                            <div
                              className={classes.bodyItem}
                            >
                              <Skeleton
                                animation="wave"
                                variant="rect"
                                width={140}
                                height='100%'
                              />
                            </div>
                            <div
                              className={classes.bodyItem}
                            >
                              <Skeleton
                                animation="wave"
                                variant="circle"
                                width={30}
                                height={30}
                              />
                            </div>
                          </div>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </div>
            );
          }}
        />
        {/* </ListLines> */}
      </>
    );
  }

  render() {
    const {
      view,
      sortBy,
      orderAsc,
      searchTerm,
      relationReversed,
    } = this.state;
    const { classes, t, entityId } = this.props;
    const paginationOptions = {
      elementId: entityId,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div style={{ height: '100%' }}>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          {view === 'lines' ? this.renderLines(paginationOptions) : ''}
        </Paper>
      </div>
    );
  }
}

RemediationEntities.propTypes = {
  entityId: PropTypes.string,
  relationship_type: PropTypes.string,
  classes: PropTypes.object,
  risk: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(RemediationEntities);
