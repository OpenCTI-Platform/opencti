import React, { Component } from 'react';
import { compose, pathOr, pipe, map } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { CenterFocusStrong } from '@mui/icons-material';
import { Field } from 'formik';
import { graphql } from 'react-relay';
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
    const { t, name, style, classes, onChange, helpertext, disabled } = this.props;
    return (
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        multiple={true}
        disabled={disabled}
        textfieldprops={{
          variant: 'standard',
          label: t('Marking'),
          helperText: helpertext,
          onFocus: this.searchMarkingDefinitions.bind(this),
        }}
        noOptionsText={t('No available options')}
        options={this.state.markingDefinitions}
        onInputChange={this.searchMarkingDefinitions.bind(this)}
        onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
        renderOption={(props, option) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <CenterFocusStrong />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
      />
    );
  }
}

export default compose(inject18n, withStyles(styles))(ObjectMarkingField);
