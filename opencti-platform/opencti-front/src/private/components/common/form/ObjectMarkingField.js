import React, { Component } from 'react';
import {
  compose, pathOr, pipe, map,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { CenterFocusStrong } from '@material-ui/icons';
import { Field } from 'formik';
import graphql from 'babel-plugin-relay/macro';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';

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

export const objectMarkingFieldAllowedMarkingsQuery = graphql`
  query ObjectMarkingFieldAllowedMarkingsQuery {
    me {
      allowed_marking {
        id
        definition_type
        definition
        x_opencti_color
      }
    }
  }
`;

class ObjectMarkingField extends Component {
  constructor(props) {
    super(props);
    const { defaultMarkingDefinitions } = props;
    this.state = {
      markingDefinitions: defaultMarkingDefinitions
        ? map(
          (n) => ({
            label: n.definition,
            value: n.id,
            color: n.x_opencti_color,
          }),
          defaultMarkingDefinitions,
        )
        : [],
    };
  }

  searchMarkingDefinitions() {
    fetchQuery(objectMarkingFieldAllowedMarkingsQuery)
      .toPromise()
      .then((data) => {
        const markingDefinitions = pipe(
          pathOr([], ['me', 'allowed_marking']),
          map((n) => ({
            label: n.definition,
            value: n.id,
            color: n.x_opencti_color,
          })),
        )(data);
        this.setState({ markingDefinitions });
      });
  }

  render() {
    const {
      t, name, style, classes, onChange, helpertext,
    } = this.props;
    return (
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        multiple={true}
        textfieldprops={{
          label: t('Marking'),
          helperText: helpertext,
          onFocus: this.searchMarkingDefinitions.bind(this),
        }}
        noOptionsText={t('No available options')}
        options={this.state.markingDefinitions}
        onInputChange={this.searchMarkingDefinitions.bind(this)}
        onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
        renderOption={(option) => (
          <React.Fragment>
            <div className={classes.icon} style={{ color: option.color }}>
              <CenterFocusStrong />
            </div>
            <div className={classes.text}>{option.label}</div>
          </React.Fragment>
        )}
      />
    );
  }
}

export default compose(inject18n, withStyles(styles))(ObjectMarkingField);
