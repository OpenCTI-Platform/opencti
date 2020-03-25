import React, { Component } from 'react';
import {
  compose, pathOr, pipe, map,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { CenterFocusStrong } from '@material-ui/icons';
import { Field } from 'formik';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';

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

class MarkingDefinitionsField extends Component {
  constructor(props) {
    super(props);
    const { defaultMarkingDefinition } = props;
    this.state = {
      markingDefinitions: defaultMarkingDefinition
        ? [
          {
            label: defaultMarkingDefinition.definition,
            value: defaultMarkingDefinition.id,
            color: defaultMarkingDefinition.color,
          },
        ]
        : [],
    };
  }

  searchMarkingDefinitions(event) {
    fetchQuery(markingDefinitionsLinesSearchQuery, {
      search: event && event.target.value !== 0 ? event.target.value : '',
    }).then((data) => {
      const markingDefinitions = pipe(
        pathOr([], ['markingDefinitions', 'edges']),
        map((n) => ({
          label: n.node.definition,
          value: n.node.id,
          color: n.node.color,
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

export default compose(inject18n, withStyles(styles))(MarkingDefinitionsField);
