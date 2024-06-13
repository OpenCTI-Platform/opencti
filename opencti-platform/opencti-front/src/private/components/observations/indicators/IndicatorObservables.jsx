import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, includes, append } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Typography from '@mui/material/Typography';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import IndicatorAddObservables from './IndicatorAddObservables';
import IndicatorObservablePopover from './IndicatorObservablePopover';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ItemEntityType from '../../../../components/ItemEntityType';

const styles = (theme) => ({
  itemHead: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
  bodyItem: {
    height: '100%',
    fontSize: 13,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  inputLabel: {
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-5px 0 0 15px',
  },
});

const inlineStyles = {
  entity_type: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  observable_value: {
    float: 'left',
    width: '50%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created_at: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class IndicatorObservablesComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { deleted: [] };
  }

  onDelete(id) {
    this.setState({ deleted: append(id, this.state.deleted) });
  }

  render() {
    const { t, fd, classes, indicator } = this.props;

    const observables = indicator.observables.edges.filter((e) => !includes(e.node.id, this.state.deleted))
      .map((e) => e.node);
    const observablesGlobalCount = indicator.observables.pageInfo.globalCount;

    return (
      <div style={{ marginTop: 20 }}>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Based on')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IndicatorAddObservables
            indicator={indicator}
            indicatorObservables={indicator.observables.edges}
          />
        </Security>
        <div className="clearfix" />
        <List style={{ marginTop: -15 }}>
          {observables.map((observable) => (
            <ListItem
              key={observable.id}
              classes={{ root: classes.item }}
              divider={true}
              button={true}
              component={Link}
              to={`/dashboard/observations/${
                observable.entity_type === 'Artifact'
                  ? 'artifacts'
                  : 'observables'
              }/${observable.id}`}
            >
              <ListItemIcon classes={{ root: classes.itemIcon }}>
                <ItemIcon type={observable.entity_type} />
              </ListItemIcon>
              <ListItemText
                primary={
                  <div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.entity_type}
                    >
                      <ItemEntityType entityType={observable.entity_type} />
                    </div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.observable_value}
                    >
                      {observable.observable_value}
                    </div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.created_at}
                    >
                      {fd(observable.created_at)}
                    </div>
                  </div>
                }
              />
              <ListItemSecondaryAction>
                <IndicatorObservablePopover
                  indicatorId={indicator.id}
                  observableId={observable.id}
                  onDelete={this.onDelete.bind(this, observable.id)}
                />
              </ListItemSecondaryAction>
            </ListItem>
          ))}
        </List>
        {
          observablesGlobalCount > 25
          && <Link to={`/dashboard/observations/indicators/${indicator.id}/knowledge`}>
              {'See more...'}
            </Link>
        }
      </div>
    );
  }
}

IndicatorObservablesComponent.propTypes = {
  indicator: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  navigate: PropTypes.func,
};

const IndicatorObservables = createFragmentContainer(
  IndicatorObservablesComponent,
  {
    indicator: graphql`
      fragment IndicatorObservables_indicator on Indicator {
        id
        name
        parent_types
        entity_type
        observables(first: 25) {
          edges {
            node {
              id
              entity_type
              parent_types
              observable_value
              created_at
              updated_at
            }
          }
          pageInfo {
            globalCount
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(IndicatorObservables);
