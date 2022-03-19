import React, { Component } from 'react';
import { compose, pathOr, pipe, map, union } from 'ramda';
import { debounce } from 'rxjs/operators';
import { Subject, timer } from 'rxjs';
import { Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';
import IdentityCreation from '../identities/IdentityCreation';
import { identitySearchIdentitiesSearchQuery } from '../identities/IdentitySearch';
import ItemIcon from '../../../../components/ItemIcon';

const SEARCH$ = new Subject().pipe(debounce(() => timer(1500)));

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

class CreatedByField extends Component {
  constructor(props) {
    super(props);
    const { defaultCreatedBy } = props;
    this.state = {
      identityCreation: false,
      keyword: '',
      identities: defaultCreatedBy
        ? [
          {
            label: defaultCreatedBy.name,
            value: defaultCreatedBy.id,
            type: defaultCreatedBy.entity_type,
          },
        ]
        : [],
    };
  }

  componentDidMount() {
    this.subscription = SEARCH$.subscribe({
      next: () => this.searchIdentities(),
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

  handleOpenIdentityCreation() {
    this.setState({ identityCreation: true });
  }

  handleCloseIdentityCreation() {
    this.setState({ identityCreation: false });
  }

  searchIdentities() {
    fetchQuery(identitySearchIdentitiesSearchQuery, {
      types: ['Individual', 'Organization'],
      search: this.state.keyword,
      first: 10,
    })
      .toPromise()
      .then((data) => {
        const identities = pipe(
          pathOr([], ['identities', 'edges']),
          map((n) => ({
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
          })),
        )(data);
        this.setState({ identities: union(this.state.identities, identities) });
      });
  }

  render() {
    const {
      t,
      name,
      style,
      classes,
      setFieldValue,
      onChange,
      helpertext,
      disabled,
    } = this.props;
    return (
      <div>
        <Field
          component={AutocompleteField}
          style={style}
          name={name}
          disabled={disabled}
          textfieldprops={{
            variant: 'standard',
            label: t('Author'),
            helperText: helpertext,
            onFocus: this.searchIdentities.bind(this),
          }}
          noOptionsText={t('No available options')}
          options={this.state.identities}
          onInputChange={this.handleSearch.bind(this)}
          openCreate={this.handleOpenIdentityCreation.bind(this)}
          onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
          renderOption={(props, option) => (
            <li {...props}>
              <div className={classes.icon}>
                <ItemIcon type={option.type} />
              </div>
              <div className={classes.text}>{option.label}</div>
            </li>
          )}
          classes={{ clearIndicator: classes.autoCompleteIndicator }}
        />
        <IdentityCreation
          contextual={true}
          onlyAuthors={true}
          inputValue={this.state.keyword}
          open={this.state.identityCreation}
          handleClose={this.handleCloseIdentityCreation.bind(this)}
          creationCallback={(data) => {
            setFieldValue(name, {
              label: data.identityAdd.name,
              value: data.identityAdd.id,
              type: data.identityAdd.entity_type,
            });
            if (typeof onChange === 'function') {
              onChange(name, {
                label: data.identityAdd.name,
                value: data.identityAdd.id,
                type: data.identityAdd.entity_type,
              });
            }
          }}
        />
      </div>
    );
  }
}

export default compose(inject18n, withStyles(styles))(CreatedByField);
