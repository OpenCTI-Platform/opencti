import React, { Component } from 'react';
import {
  compose, pathOr, pipe, map, union,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import Autocomplete from '@material-ui/lab/Autocomplete';
import TextField from '@material-ui/core/TextField';
import Popover from '@material-ui/core/Popover';
import IconButton from '@material-ui/core/IconButton';
import { FilterList } from '@material-ui/icons';
import * as PropTypes from 'prop-types';
import { fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { identityCreationIdentitiesSearchQuery } from '../identities/IdentityCreation';
import { tagsSearchQuery } from '../../settings/Tags';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import ItemIcon from '../../../../components/ItemIcon';

const styles = (theme) => ({
  filters: {
    float: 'left',
    margin: '-8px 0 0 -5px',
  },
  container: {
    width: 490,
    padding: 20,
  },
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
});

class Filters extends Component {
  constructor(props) {
    super(props);
    this.anchorEl = React.createRef();
    this.state = {
      open: false,
      anchorEl: null,
      entities: {},
    };
  }

  handleOpenFilters(event) {
    this.setState({ open: true, anchorEl: event.currentTarget });
  }

  handleCloseFilters() {
    this.setState({ open: false, anchorEl: null });
  }

  searchEntities(filterKey, event) {
    switch (filterKey) {
      case 'tags':
        fetchQuery(tagsSearchQuery, {
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        }).then((data) => {
          const entities = pipe(
            pathOr([], ['tags', 'edges']),
            map((n) => ({
              label: n.node.value,
              value: n.node.id,
              type: 'tag',
              color: n.node.color,
            })),
          )(data);
          this.setState({
            entities: { tags: union(this.state.entities, entities) },
          });
        });
        break;
      case 'markingDefinitions':
        fetchQuery(markingDefinitionsLinesSearchQuery, {
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        }).then((data) => {
          const entities = pipe(
            pathOr([], ['markingDefinitions', 'edges']),
            map((n) => ({
              label: n.node.definition,
              value: n.node.id,
              type: 'marking-definition',
              color: n.node.color,
            })),
          )(data);
          this.setState({
            entities: {
              markingDefinitions: union(this.state.entities, entities),
            },
          });
        });
        break;
      case 'createdBy':
        fetchQuery(identityCreationIdentitiesSearchQuery, {
          search: event && event.target.value !== 0 ? event.target.value : '',
          first: 10,
        }).then((data) => {
          const entities = pipe(
            pathOr([], ['identities', 'edges']),
            map((n) => ({
              label: n.node.name,
              value: n.node.id,
              type: n.node.entity_type,
            })),
          )(data);
          this.setState({
            entities: { createdBy: union(this.state.entities, entities) },
          });
        });
        break;
      default:
        this.setState({ entities: union(this.state.entities, []) });
    }
  }

  handleChange(filterKey, event, value) {
    this.props.handleAddFilter(filterKey, value.value, value.label, event);
    this.handleCloseFilters();
  }

  render() {
    const { t, classes, availableFilterKeys } = this.props;
    const { open, anchorEl, entities } = this.state;
    return (
      <div className={classes.filters}>
        <IconButton color="primary" onClick={this.handleOpenFilters.bind(this)}>
          <FilterList />
        </IconButton>
        <Popover
          classes={{ paper: classes.container }}
          open={open}
          anchorEl={anchorEl}
          onClose={this.handleCloseFilters.bind(this)}
          anchorOrigin={{
            vertical: 'bottom',
            horizontal: 'center',
          }}
          transformOrigin={{
            vertical: 'top',
            horizontal: 'center',
          }}
        >
          <Grid container={true} spacing={3}>
            {availableFilterKeys.map((filterKey) => (
              <Grid key={filterKey} item={true} xs={6}>
                <Autocomplete
                  className={classes.autocomplete}
                  selectOnFocus={true}
                  autoHighlight={true}
                  getOptionLabel={(option) => (option.label ? option.label : '')
                  }
                  noOptionsText={t('No available options')}
                  options={entities[filterKey] ? entities[filterKey] : []}
                  onInputChange={this.searchEntities.bind(this, filterKey)}
                  onChange={this.handleChange.bind(this, filterKey)}
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      label={t(`filter_${filterKey}`)}
                      variant="outlined"
                      size="small"
                      fullWidth={true}
                      onFocus={this.searchEntities.bind(this, filterKey)}
                    />
                  )}
                  renderOption={(option) => (
                    <React.Fragment>
                      <div
                        className={classes.icon}
                        style={{ color: option.color }}
                      >
                        <ItemIcon type={option.type} />
                      </div>
                      <div className={classes.text}>{option.label}</div>
                    </React.Fragment>
                  )}
                />
              </Grid>
            ))}
          </Grid>
        </Popover>
      </div>
    );
  }
}

Filters.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  availableFilterKeys: PropTypes.array,
  handleAddFilter: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(Filters);
