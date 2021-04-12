import React, { Component } from 'react';
import {
  compose, pathOr, pipe, map, union,
} from 'ramda';
import { Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';
import IdentityCreation, {
  identityCreationIdentitiesSearchQuery,
} from '../identities/IdentityCreation';
import ItemIcon from '../../../../components/ItemIcon';

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
      identityInput: '',
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

  handleOpenIdentityCreation() {
    this.setState({ identityCreation: true });
  }

  handleCloseIdentityCreation() {
    this.setState({ identityCreation: false });
  }

  searchIdentities(event) {
    this.setState({
      identityInput:
        event && event.target.value !== 0 ? event.target.value : '',
    });
    fetchQuery(identityCreationIdentitiesSearchQuery, {
      types: ['Individual', 'Organization'],
      search: event && event.target.value !== 0 ? event.target.value : '',
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
    } = this.props;
    return (
      <div>
        <Field
          component={AutocompleteField}
          style={style}
          name={name}
          textfieldprops={{
            label: t('Author'),
            helperText: helpertext,
            onFocus: this.searchIdentities.bind(this),
          }}
          noOptionsText={t('No available options')}
          options={this.state.identities}
          onInputChange={this.searchIdentities.bind(this)}
          openCreate={this.handleOpenIdentityCreation.bind(this)}
          onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
          renderOption={(option) => (
            <React.Fragment>
              <div className={classes.icon}>
                <ItemIcon type={option.type} />
              </div>
              <div className={classes.text}>{option.label}</div>
            </React.Fragment>
          )}
          classes={{ clearIndicator: classes.autoCompleteIndicator }}
        />
        <IdentityCreation
          contextual={true}
          onlyAuthors={true}
          inputValue={this.state.identityInput}
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
