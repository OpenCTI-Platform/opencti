import React, { Component } from 'react';
import {
  compose,
  pathOr,
  pipe,
  map,
  sortWith,
  ascend,
  path,
  union,
} from 'ramda';
import { Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import { LanguageOutlined } from '@material-ui/icons';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { externalReferencesSearchQuery } from '../../analysis/ExternalReferences';

const styles = () => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
});

class ExternalReferencesField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      externalReferences: [],
    };
  }

  searchExternalReferences(event) {
    fetchQuery(externalReferencesSearchQuery, {
      search: event && event.target.value,
    })
      .toPromise()
      .then((data) => {
        const externalReferences = pipe(
          pathOr([], ['externalReferences', 'edges']),
          sortWith([ascend(path(['node', 'source_name']))]),
          map((n) => ({
            label: `[${n.node.source_name}] ${truncate(
              n.node.description || n.node.url || n.node.external_id,
              150,
            )}`,
            value: n.node.id,
          })),
        )(data);
        this.setState({
          externalReferences: union(
            this.state.externalReferences,
            externalReferences,
          ),
        });
      });
  }

  render() {
    const {
      t,
      name,
      style,
      classes,
      variant,
      onChange,
      helpertext,
    } = this.props;
    return (
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        variant='outlined'
        multiple={true}
        textfieldprops={{
          label: t('Add External References'),
          helperText: helpertext,
          onFocus: this.searchExternalReferences.bind(this),
        }}
        noOptionsText={t('No available options')}
        options={this.state.externalReferences}
        onInputChange={this.searchExternalReferences.bind(this)}
        onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
        renderOption={(option) => (
          <React.Fragment>
            <div className={classes.icon} style={{ color: option.color }}>
              <LanguageOutlined />
            </div>
            <div className={classes.text}>{option.label}</div>
          </React.Fragment>
        )}
      />
    );
  }
}

export default compose(inject18n, withStyles(styles))(ExternalReferencesField);
