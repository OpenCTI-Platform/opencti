import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, map, sortWith, ascend, descend, prop,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import {
  ArrowDropDown,
  ArrowDropUp,
  KeyboardArrowRight,
} from '@material-ui/icons';
import { ShieldSearch } from 'mdi-material-ui';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import ItemScore from '../../../../components/ItemScore';
import ItemPatternType from '../../../../components/ItemPatternType';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '6px 0 0 0',
    padding: '15px 15px 15px 15px',
    borderRadius: 6,
  },
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
    right: 10,
    marginRight: 0,
  },
  inputLabel: {
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-5px 0 0 15px',
  },
});

const inlineStylesHeaders = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  pattern_type: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
  name: {
    float: 'left',
    width: '40%',
    fontSize: 12,
    fontWeight: '700',
  },
  valid_from: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  valid_until: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  score: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

const inlineStyles = {
  pattern_type: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  name: {
    float: 'left',
    width: '40%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  valid_from: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  valid_until: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  score: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class StixObservableIndicatorsComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { sortBy: 'name', orderAsc: false };
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label, isSortable) {
    const { t } = this.props;
    const sortComponent = this.state.orderAsc ? (
      <ArrowDropDown style={inlineStylesHeaders.iconSort} />
    ) : (
      <ArrowDropUp style={inlineStylesHeaders.iconSort} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={this.reverseBy.bind(this, field)}
        >
          <span>{t(label)}</span>
          {this.state.sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t(label)}</span>
      </div>
    );
  }

  render() {
    const {
      t, fd, classes, stixObservable,
    } = this.props;
    const indicators = map((n) => n.node, stixObservable.indicators.edges);
    const sort = sortWith(
      this.state.orderAsc
        ? [ascend(prop(this.state.sortBy))]
        : [descend(prop(this.state.sortBy))],
    );
    const sortedIndicators = sort(indicators);
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Indicators composed with this observable')}
        </Typography>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <List>
            <ListItem
              classes={{ root: classes.itemHead }}
              divider={false}
              style={{ paddingTop: 0 }}
            >
              <ListItemIcon>
                <span
                  style={{
                    padding: '0 8px 0 8px',
                    fontWeight: 700,
                    fontSize: 12,
                  }}
                >
                  #
                </span>
              </ListItemIcon>
              <ListItemText
                primary={
                  <div>
                    {this.SortHeader('pattern_type', 'Pattern type', true)}
                    {this.SortHeader('name', 'Name', true)}
                    {this.SortHeader('valid_from', 'Valid from', true)}
                    {this.SortHeader('valid_until', 'Valid until', true)}
                    {this.SortHeader('score', 'Score', true)}
                  </div>
                }
              />
            </ListItem>
            {sortedIndicators.map((indicator) => (
              <ListItem
                key={indicator.id}
                classes={{ root: classes.item }}
                divider={true}
                button={true}
                component={Link}
                to={`/dashboard/signatures/indicators/${indicator.id}`}
              >
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <ShieldSearch />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.pattern_type}
                      >
                        <ItemPatternType variant="inList" label={indicator.pattern_type} />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.name}
                      >
                        {indicator.name}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.valid_from}
                      >
                        {fd(indicator.valid_from)}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.valid_until}
                      >
                        {fd(indicator.valid_until)}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.score}
                      >
                        <ItemScore variant="inList" score={indicator.score} />
                      </div>
                    </div>
                  }
                />
                <ListItemIcon classes={{ root: classes.goIcon }}>
                  <KeyboardArrowRight />
                </ListItemIcon>
              </ListItem>
            ))}
          </List>
        </Paper>
      </div>
    );
  }
}

StixObservableIndicatorsComponent.propTypes = {
  stixObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

const StixObservableIndicators = createFragmentContainer(
  StixObservableIndicatorsComponent,
  {
    stixObservable: graphql`
      fragment StixObservableIndicators_stixObservable on StixObservable {
        id
        indicators {
          edges {
            node {
              id
              name
              pattern_type
              valid_from
              valid_until
              score
              created
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(StixObservableIndicators);
