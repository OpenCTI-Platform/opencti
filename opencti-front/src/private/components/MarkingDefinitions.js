/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { ArrowDropDown, ArrowDropUp } from '@material-ui/icons';
import { QueryRenderer } from '../../relay/environment';
import MarkingDefinitionsLines, {
  markingDefinitionsLinesQuery,
} from './marking_definition/MarkingDefinitionsLines';
import inject18n from '../../components/i18n';
import MarkingDefinitionCreation from './marking_definition/MarkingDefinitionCreation';

const styles = () => ({
  linesContainer: {
    marginTop: 0,
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
});

const inlineStyles = {
  iconSort: {
    position: 'absolute',
    margin: '-3px 0 0 5px',
    padding: 0,
    top: '0px',
  },
  definition_type: {
    float: 'left',
    width: '25%',
    fontSize: 12,
    fontWeight: '700',
  },
  definition: {
    float: 'left',
    width: '25%',
    fontSize: 12,
    fontWeight: '700',
  },
  color: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  level: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
  created: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

class MarkingDefinitions extends Component {
  constructor(props) {
    super(props);
    this.state = { sortBy: 'definition_type', orderAsc: true };
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label) {
    const { t } = this.props;
    return (
      <div
        style={inlineStyles[field]}
        onClick={this.reverseBy.bind(this, field)}
      >
        <span>{t(label)}</span>
        {this.state.sortBy === field ? (
          this.state.orderAsc ? (
            <ArrowDropDown style={inlineStyles.iconSort} />
          ) : (
            <ArrowDropUp style={inlineStyles.iconSort} />
          )
        ) : (
          ''
        )}
      </div>
    );
  }

  render() {
    const { classes } = this.props;
    const paginationOptions = {
      orderBy: this.state.sortBy,
      orderMode: this.state.orderAsc ? 'asc' : 'desc',
    };
    return (
      <div>
        <List classes={{ root: classes.linesContainer }}>
          <ListItem
            classes={{ default: classes.item }}
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
                  {this.SortHeader('definition_type', 'Type')}
                  {this.SortHeader('definition', 'Definition')}
                  {this.SortHeader('color', 'Color')}
                  {this.SortHeader('level', 'Level')}
                  {this.SortHeader('created', 'Creation date')}
                </div>
              }
            />
          </ListItem>
          <QueryRenderer
            query={markingDefinitionsLinesQuery}
            variables={{
              count: 25,
              orderBy: this.state.sortBy,
              orderMode: this.state.orderAsc ? 'asc' : 'desc',
            }}
            render={({ props }) => {
              if (props) {
                // Done
                return (
                  <MarkingDefinitionsLines
                    data={props}
                    paginationOptions={paginationOptions}
                  />
                );
              }
              // Loading
              return <MarkingDefinitionsLines data={null} dummy={true} />;
            }}
          />
        </List>
        <MarkingDefinitionCreation paginationOptions={paginationOptions} />
      </div>
    );
  }
}

MarkingDefinitions.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(MarkingDefinitions);
