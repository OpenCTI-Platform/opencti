import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withRouter } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ArrowRightAltOutlined } from '@mui/icons-material';
import { interval } from 'rxjs';
import Slide from '@mui/material/Slide';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { graphql, createRefetchContainer } from 'react-relay';
import Chip from '@mui/material/Chip';
import inject18n from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import SubTypePopover from './SubTypePopover';
import { hexToRGB } from '../../../../utils/Colors';
import ItemIcon from '../../../../components/ItemIcon';
import { commitMutation } from '../../../../relay/environment';

const interval$ = interval(FIVE_SECONDS);

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  root: {
    marginBottom: 50,
  },
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
    width: '30%',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    height: 20,
    lineHeight: '20px',
  },
  statuses: {
    float: 'left',
    width: '50%',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  reference: {
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingLeft: 20,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
});

const workflowLinesFieldPatch = graphql`
  mutation WorkflowLinesFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        platform_enable_reference
      }
    }
  }
`;

class WorkflowLinesComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleSubmitReference(type, event) {
    const { id, platform_enable_reference: currentReference } = this.props.data.settings;
    const { checked } = event.target;
    let reference;
    if (checked) {
      reference = R.uniq([...(currentReference || []), type]);
    } else {
      reference = R.uniq(R.filter((n) => n !== type, currentReference));
    }
    commitMutation({
      mutation: workflowLinesFieldPatch,
      variables: {
        id,
        input: {
          key: 'platform_enable_reference',
          value: reference,
        },
      },
    });
  }

  render() {
    const { classes, data, keyword, t } = this.props;
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
                                  backgroundColor: hexToRGB(
                                    status.template.color,
                                  ),
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
    ...WorkflowLines_data
  }
`;

const WorkflowLines = createRefetchContainer(
  WorkflowLinesComponent,
  {
    data: graphql`
      fragment WorkflowLines_data on Query {
        settings {
          id
          platform_enable_reference
        }
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
