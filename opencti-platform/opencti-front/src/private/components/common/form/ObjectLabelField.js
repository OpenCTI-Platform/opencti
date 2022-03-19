import React, { Component } from 'react';
import { compose, pathOr, pipe, map, union, append } from 'ramda';
import { Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import { Label } from 'mdi-material-ui';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';
import { labelsSearchQuery } from '../../settings/LabelsQuery';
import LabelCreation from '../../settings/labels/LabelCreation';

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
  autoCompleteIndicator: {
    display: 'none',
  },
});

class ObjectLabelField extends Component {
  constructor(props) {
    super(props);
    this.state = { labelCreation: false, labelInput: '', labels: [] };
  }

  handleOpenLabelCreation() {
    this.setState({ labelCreation: true });
  }

  handleCloseLabelCreation() {
    this.setState({ labelCreation: false });
  }

  searchLabels(event) {
    this.setState({
      labelInput: event && event.target.value !== 0 ? event.target.value : '',
    });
    fetchQuery(labelsSearchQuery, {
      search: event && event.target.value !== 0 ? event.target.value : '',
    })
      .toPromise()
      .then((data) => {
        const labels = pipe(
          pathOr([], ['labels', 'edges']),
          map((n) => ({
            label: n.node.value,
            value: n.node.id,
            color: n.node.color,
          })),
        )(data);
        this.setState({
          labels: union(this.state.labels, labels),
        });
      });
  }

  render() {
    const { t, name, style, classes, setFieldValue, values, helpertext } = this.props;
    return (
      <div>
        <Field
          component={AutocompleteField}
          style={style}
          name={name}
          multiple={true}
          textfieldprops={{
            variant: 'standard',
            label: t('Labels'),
            helperText: helpertext,
            onFocus: this.searchLabels.bind(this),
          }}
          noOptionsText={t('No available options')}
          options={this.state.labels}
          onInputChange={this.searchLabels.bind(this)}
          openCreate={this.handleOpenLabelCreation.bind(this)}
          renderOption={(props, option) => (
            <li {...props}>
              <div className={classes.icon} style={{ color: option.color }}>
                <Label />
              </div>
              <div className={classes.text}>{option.label}</div>
            </li>
          )}
          classes={{ clearIndicator: classes.autoCompleteIndicator }}
        />
        <LabelCreation
          contextual={true}
          inputValue={this.state.labelInput}
          open={this.state.labelCreation}
          handleClose={this.handleCloseLabelCreation.bind(this)}
          creationCallback={(data) => {
            setFieldValue(
              name,
              append(
                {
                  label: data.labelAdd.value,
                  value: data.labelAdd.id,
                },
                values,
              ),
            );
          }}
        />
      </div>
    );
  }
}

export default compose(inject18n, withStyles(styles))(ObjectLabelField);
