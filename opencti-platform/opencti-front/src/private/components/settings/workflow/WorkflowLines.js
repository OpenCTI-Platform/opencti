import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { ArrowRightAltOutlined } from '@material-ui/icons';
import { interval } from 'rxjs';
import Slide from '@material-ui/core/Slide';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { createRefetchContainer } from 'react-relay';
import Chip from '@material-ui/core/Chip';
import inject18n from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import SubTypePopover from './SubTypePopover';
import { hexToRGB } from '../../../../utils/Colors';
import ItemIcon from '../../../../components/ItemIcon';

const interval$ = interval(FIVE_SECONDS);

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    cursor: 'default',
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  labelContainer: {
    float: 'left',
    height: 20,
  },
  label: {
    float: 'left',
    fontSize: 12,
    height: 20,
  },
  arrow: {
    float: 'left',
    margin: '-2px 7px 0 7px',
  },
  subtype: {
    width: '20%',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    height: 20,
    lineHeight: '20px',
  },
  statuses: {
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
});

class WorkflowLinesComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    const {
      classes, data, keyword, t,
    } = this.props;
    const filterByKeyword = (n) => keyword === ''
      || n.label.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || n.tlabel.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
    const subTypesEdges = data.subTypes.edges;
    const sortByLabel = R.sortBy(R.compose(R.toLower, R.prop('tlabel')));
    const translatedOrderedList = R.pipe(
      R.map((n) => n.node),
      R.map((n) => R.assoc('tlabel', t(`entity_${n.label}`), n)),
      sortByLabel,
      R.filter(filterByKeyword),
    )(subTypesEdges);
    return (
      <div>
        <List
          component="nav"
          aria-labelledby="nested-list-subheader"
          className={classes.root}
        >
          {translatedOrderedList.map((subType) => {
            const statuses = R.pipe(R.map((n) => n.node))(
              subType.statuses.edges,
            );
            return (
              <ListItem
                key={subType.id}
                classes={{ root: classes.item }}
                divider={true}
              >
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <ItemIcon type={subType.id} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div className={classes.subtype}>{subType.tlabel}</div>
                      <div className={classes.statuses}>
                        {statuses.length > 0 ? (
                          statuses.map((status) => (
                            <div
                              key={status.id}
                              className={classes.labelContainer}
                            >
                              <Chip
                                classes={{ root: classes.label }}
                                variant="outlined"
                                label={t(`status_${status.template.name}`)}
                                style={{
                                  color: status.template.color,
                                  borderColor: status.template.color,
                                  backgroundColor: hexToRGB(status.template.color),
                                }}
                              />
                              {R.last(statuses).id !== status.id && (
                                <div className={classes.arrow}>
                                  <ArrowRightAltOutlined />
                                </div>
                              )}
                            </div>
                          ))
                        ) : (
                          <Chip
                            classes={{ root: classes.label }}
                            variant="outlined"
                            label={t('Disabled')}
                          />
                        )}
                      </div>
                    </div>
                  }
                />
                <ListItemSecondaryAction>
                  <SubTypePopover subTypeId={subType.id} />
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
      </div>
    );
  }
}

WorkflowLinesComponent.propTypes = {
  t: PropTypes.func,
  classes: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
  nsdt: PropTypes.func,
  data: PropTypes.object,
};

export const workflowLinesQuery = graphql`
  query WorkflowLinesQuery {
    ...WorkflowLines_subTypes
  }
`;

const WorkflowLines = createRefetchContainer(
  WorkflowLinesComponent,
  {
    data: graphql`
      fragment WorkflowLines_subTypes on Query {
        subTypes {
          edges {
            node {
              id
              label
              workflowEnabled
              statuses {
                edges {
                  node {
                    id
                    order
                    template {
                      name
                      color
                    }
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  workflowLinesQuery,
);

export default R.compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(WorkflowLines);
