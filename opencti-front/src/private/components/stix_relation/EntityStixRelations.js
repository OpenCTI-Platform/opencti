/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, head, map, includes, filter,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Select from '@material-ui/core/Select';
import Input from '@material-ui/core/Input';
import Chip from '@material-ui/core/Chip';
import MenuItem from '@material-ui/core/MenuItem';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Switch from '@material-ui/core/Switch';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { ArrowDropDown, ArrowDropUp } from '@material-ui/icons';
import { QueryRenderer, fetchQuery } from '../../../relay/environment';
import { currentYear, parse, yearFormat } from '../../../utils/Time';
import inject18n from '../../../components/i18n';
import EntityStixRelationsLines, { entityStixRelationsLinesQuery } from './EntityStixRelationsLines';

const styles = theme => ({
  container: {
    position: 'relative',
  },
  filters: {
    position: 'absolute',
    top: -75,
    right: 0,
  },
  linesContainer: {
    marginTop: 20,
    paddingTop: 0,
  },
  item: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  inputLabel: {
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-5px 0 0 15px',
  },
  chips: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  chip: {
    margin: theme.spacing.unit / 4,
  },
});

const inlineStyles = {
  iconSort: {
    position: 'absolute',
    margin: '-3px 0 0 5px',
    padding: 0,
    top: '0px',
  },
  name: {
    float: 'left',
    width: '30%',
    fontSize: 12,
    fontWeight: '700',
  },
  type: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  first_seen: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  last_seen: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  weight: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

const firstStixRelationQuery = graphql`
    query EntityStixRelationsFirstStixRelationQuery($toTypes: [String], $fromId: String, $relationType: String, $first: Int, $orderBy: StixRelationsOrdering, $orderMode: OrderingMode) {
        stixRelations(toTypes: $toTypes, fromId: $fromId, relationType: $relationType, first: $first, orderBy: $orderBy, orderMode: $orderMode) {
            edges {
                node {
                    id
                    first_seen
                }
            }
        }
    }
`;

class EntityStixRelations extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: 'first_seen',
      orderAsc: false,
      firstSeen: 'All years',
      firstSeenFirstYear: currentYear(),
      firstSeenStart: null,
      firstSeenStop: null,
      weights: [0],
      openWeights: false,
      inferred: false,
    };
  }

  componentDidMount() {
    const { entityId, relationType, targetEntityTypes } = this.props;
    fetchQuery(firstStixRelationQuery, {
      toTypes: targetEntityTypes || null,
      fromId: entityId,
      relationType,
      first: 1,
      orderBy: 'first_seen',
      orderMode: 'asc',
    }).then((data) => {
      if (data.stixRelations.edges.length > 0) {
        this.setState({ firstSeenFirstYear: yearFormat(head(data.stixRelations.edges).node.first_seen) });
      }
    });
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label, isSortable) {
    const { t } = this.props;
    if (isSortable) {
      return (
        <div style={inlineStyles[field]} onClick={this.reverseBy.bind(this, field)}>
          <span>{t(label)}</span>
          {this.state.sortBy === field ? this.state.orderAsc ? <ArrowDropDown style={inlineStyles.iconSort}/> : <ArrowDropUp style={inlineStyles.iconSort}/> : ''}
        </div>
      );
    }
    return (
      <div style={inlineStyles[field]}>
        <span>{t(label)}</span>
      </div>
    );
  }

  handleChangeYear(event) {
    const { value } = event.target;
    if (value !== 'All years') {
      const startDate = `${value}-01-01`;
      const endDate = `${value}-12-31`;
      this.setState({
        firstSeen: value,
        firstSeenStart: parse(startDate).format(),
        firstSeenStop: parse(endDate).format(),
      });
    } else {
      this.setState({
        firstSeen: value,
        firstSeenStart: null,
        firstSeenStop: null,
      });
    }
  }

  handleOpenWeights() {
    this.setState({ openWeights: true });
  }

  handleCloseWeights() {
    this.setState({ openWeights: false });
  }

  handleChangeWeights(event) {
    const { value } = event.target;
    if (includes(0, this.state.weights) || !includes(0, value)) {
      const weights = filter(v => v !== 0, value);
      if (weights.length > 0) {
        return this.setState({ openWeights: false, weights });
      }
    }
    return this.setState({ openWeights: false, weights: [0] });
  }

  handleChangeInferred() {
    this.setState({ inferred: !this.state.inferred });
  }

  render() {
    const {
      t, classes, entityId, relationType, entityLink, targetEntityTypes,
    } = this.props;
    const startYear = this.state.firstSeenFirstYear === currentYear() ? this.state.firstSeenFirstYear - 1 : this.state.firstSeenFirstYear;
    const yearsList = [];
    for (let i = startYear; i <= currentYear(); i++) {
      yearsList.push(i);
    }

    const paginationOptions = {
      inferred: this.state.inferred,
      toTypes: targetEntityTypes || null,
      fromId: entityId,
      relationType,
      firstSeenStart: this.state.firstSeenStart || null,
      firstSeenStop: this.state.firstSeenStop || null,
      weights: includes(0, this.state.weights) ? null : this.state.weights,
      orderBy: this.state.sortBy,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    return (
      <div className={classes.container}>
        <div className={classes.filters}>
          <FormControlLabel
            style={{ paddingTop: 5 }}
            control={
              <Switch
                checked={this.state.inferred}
                onChange={this.handleChangeInferred.bind(this)}
                color='primary'
              />
            }
            label={t('Inferences')}
          />
          <Select
            style={{ height: 50 }}
            multiple={true}
            value={this.state.weights}
            open={this.state.openWeights}
            onClose={this.handleCloseWeights.bind(this)}
            onOpen={this.handleOpenWeights.bind(this)}
            onChange={this.handleChangeWeights.bind(this)}
            input={<Input id='weights'/>}
            renderValue={selected => (
              <div className={classes.chips}>
                {selected.map(value => (
                  <Chip key={value} label={t(`confidence_${value}`)} className={classes.chip}/>
                ))}
              </div>
            )}
          >
            <MenuItem value={0}>{t('All confidence levels')}</MenuItem>
            <MenuItem value={1}>{t('Very low')}</MenuItem>
            <MenuItem value={2}>{t('Low')}</MenuItem>
            <MenuItem value={3}>{t('Medium')}</MenuItem>
            <MenuItem value={4}>{t('High')}</MenuItem>
            <MenuItem value={5}>{t('Very high')}</MenuItem>
          </Select>
          <Select
            style={{ width: 170, height: 52, marginLeft: 20 }}
            value={this.state.firstSeen}
            onChange={this.handleChangeYear.bind(this)}
            renderValue={selected => (
              <div className={classes.chips}>
                <Chip key={selected} label={t(selected)} className={classes.chip}/>
              </div>
            )}
          >
            <MenuItem value='All years'>{t('All years')}</MenuItem>
            {map(year => (<MenuItem key={year} value={year}>{year}</MenuItem>), yearsList)}
          </Select>
        </div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem classes={{ default: classes.item }} divider={false} style={{ paddingTop: 0 }}>
            <ListItemIcon>
              <span style={{ padding: '0 8px 0 8px', fontWeight: 700, fontSize: 12 }}>#</span>
            </ListItemIcon>
            <ListItemText primary={
              <div>
                {this.SortHeader('name', 'Name', false)}
                {this.SortHeader('type', 'Entity type', false)}
                {this.SortHeader('first_seen', 'First obs.', !this.state.inferred)}
                {this.SortHeader('last_seen', 'Last obs.', !this.state.inferred)}
                {this.SortHeader('weight', 'Confidence level', !this.state.inferred)}
              </div>
            }/>
            <ListItemSecondaryAction>
              &nbsp;
            </ListItemSecondaryAction>
          </ListItem>
          <QueryRenderer
            query={entityStixRelationsLinesQuery}
            variables={{ count: 25, ...paginationOptions }}
            render={({ props }) => {
              if (props) {
                return <EntityStixRelationsLines
                  data={props}
                  paginationOptions={paginationOptions}
                  entityLink={entityLink}
                />;
              }
              return <EntityStixRelationsLines data={null} dummy={true}/>;
            }}
          />
        </List>
      </div>
    );
  }
}

EntityStixRelations.propTypes = {
  entityId: PropTypes.string,
  targetEntityTypes: PropTypes.array,
  entityLink: PropTypes.string,
  relationType: PropTypes.string,
  classes: PropTypes.object,
  reportClass: PropTypes.string,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixRelations);
