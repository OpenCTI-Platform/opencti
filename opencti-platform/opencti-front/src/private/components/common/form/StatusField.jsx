import React, { Component } from 'react';
import * as R from 'ramda';
import { debounce } from 'rxjs/operators';
import { Subject, timer } from 'rxjs';
import { Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import { graphql } from 'react-relay';
import Avatar from '@mui/material/Avatar';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';
import { hexToRGB } from '../../../../utils/Colors';

const SEARCH$ = new Subject().pipe(debounce(() => timer(1500)));

export const statusFieldStatusesSearchQuery = graphql`
  query StatusFieldStatusesSearchQuery(
    $first: Int
    $orderBy: StatusOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    statuses(
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          order
          type
          template {
            name
            color
          }
        }
      }
    }
  }
`;

const styles = (theme) => ({
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
  autoCompleteIndicator: {
    display: 'none',
  },
});

class StatusField extends Component {
  constructor(props) {
    super(props);
    const { defaultStatus } = props;
    this.state = {
      keyword: '',
      statuses: defaultStatus
        ? [
          {
            label: defaultStatus.template.name,
            color: defaultStatus.template.color,
            value: defaultStatus.id,
            order: defaultStatus.order,
            type: defaultStatus.type,
          },
        ]
        : [],
    };
  }

  componentDidMount() {
    this.subscription = SEARCH$.subscribe({
      next: () => this.searchStatuses(),
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleSearch(event) {
    if (event && event.target && event.target.value) {
      this.setState({ keyword: event.target.value });
      SEARCH$.next({ action: 'Search' });
    }
  }

  searchStatuses() {
    fetchQuery(statusFieldStatusesSearchQuery, {
      first: 100,
      filters: this.props.type
        ? {
          mode: 'and',
          filterGroups: [],
          filters: [{ key: 'type', values: [this.props.type] }],
        }
        : null,
      orderBy: 'order',
      orderMode: 'asc',
      search: this.state.keyword,
    })
      .toPromise()
      .then((data) => {
        const statuses = R.pipe(
          R.pathOr([], ['statuses', 'edges']),
          R.filter((n) => !R.isNil(n.node.template)),
          R.map((n) => ({
            label: n.node.template.name,
            value: n.node.id,
            order: n.node.order,
            color: n.node.template.color,
            type: n.node.type,
          })),
        )(data);
        statuses.sort((a, b) => {
          return a.type < b.type ? -1 : 1;
        });
        this.setState({ statuses: R.union(this.state.statuses, statuses) });
      });
  }

  render() {
    const { t, name, style, classes, onChange, helpertext, type, required } = this.props;
    return (
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        required={required}
        textfieldprops={{
          variant: 'standard',
          label: t('Status'),
          helperText: helpertext,
          onFocus: this.searchStatuses.bind(this),
        }}
        noOptionsText={t('No available options')}
        options={this.state.statuses}
        onInputChange={this.handleSearch.bind(this)}
        groupBy={type ? undefined : (option) => option.type}
        onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
        renderOption={(props, option) => (
          <li {...props}>
            <div className={classes.icon}>
              <Avatar
                variant="square"
                style={{
                  color: option.color,
                  borderColor: option.color,
                  backgroundColor: hexToRGB(option.color),
                }}
              >
                {option.order}
              </Avatar>
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
    );
  }
}

export default R.compose(inject18n, withStyles(styles))(StatusField);
