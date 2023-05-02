import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field } from 'formik';
import { assoc, compose, map, pipe, prop, sortBy, toLower } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import MenuItem from '@mui/material/MenuItem';
import inject18n from '../../../components/i18n';
import SelectField from '../../../components/SelectField';
import { QueryRenderer } from '../../../relay/environment';
import { stixCyberObservablesLinesSubTypesQuery } from './stix_cyber_observables/StixCyberObservablesLines';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class TypesField extends Component {
  render() {
    const { t, name, label, containerstyle } = this.props;
    return (
      <QueryRenderer
        query={stixCyberObservablesLinesSubTypesQuery}
        variables={{ type: 'Stix-Cyber-Observable' }}
        render={({ props }) => {
          if (props && props.subTypes) {
            const subTypesEdges = props.subTypes.edges;
            const sortByLabel = sortBy(compose(toLower, prop('tlabel')));
            const translatedOrderedList = pipe(
              map((n) => n.node),
              map((n) => assoc('tlabel', t(`entity_${n.label}`), n)),
              sortByLabel,
            )(subTypesEdges);
            return (
              <Field
                component={SelectField}
                variant="standard"
                name={name}
                label={label}
                fullWidth={true}
                containerstyle={containerstyle}
              >
                {translatedOrderedList.map((subType) => (
                  <MenuItem key={subType.id} value={subType.label}>
                    {subType.tlabel}
                  </MenuItem>
                ))}
              </Field>
            );
          }
          return <div />;
        }}
      />
    );
  }
}

TypesField.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(TypesField);
