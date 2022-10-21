import React, { Component } from 'react';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { AccountBalanceOutlined } from '@mui/icons-material';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
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
  message: {
    width: '100%',
    overflow: 'hidden',
  },
});

export const objectOrganizationFieldQuery = graphql`
  query ObjectOrganizationFieldQuery {
    organizations {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

class ObjectOrganizationField extends Component {
  constructor(props) {
    super(props);
    const { defaultOrganizations } = props;
    const organizations = (defaultOrganizations ?? []).map((n) => ({
      label: n.name,
      value: n.id /* color: n.x_opencti_color */,
    }));
    this.state = { organizations };
  }

  searchOrganizations() {
    fetchQuery(objectOrganizationFieldQuery)
      .toPromise()
      .then((data) => {
        const organizations = data.organizations.edges.map((n) => ({
          label: n.node.name,
          value: n.node.id,
          // color: n.x_opencti_color,
        }));
        this.setState({ organizations });
      });
  }

  render() {
    const {
      t,
      name,
      label,
      style,
      classes,
      onChange,
      helpertext,
      disabled,
      outlined = true,
    } = this.props;
    if (outlined === false) {
      return (
        <Field
          component={AutocompleteField}
          name={name}
          multiple={true}
          disabled={disabled}
          style={style}
          textfieldprops={{
            variant: 'standard',
            label: t(label ?? 'Organizations restriction'),
            helperText: helpertext,
            fullWidth: true,
            onFocus: this.searchOrganizations.bind(this),
          }}
          noOptionsText={t('No available options')}
          options={this.state.organizations}
          onInputChange={this.searchOrganizations.bind(this)}
          onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
          renderOption={(props, option) => (
            <li {...props}>
              <div className={classes.icon} style={{ color: option.color }}>
                <AccountBalanceOutlined />
              </div>
              <div className={classes.text}>{option.label}</div>
            </li>
          )}
        />
      );
    }
    return (
      <Alert severity="warning" variant="outlined" style={style} classes={{ message: classes.message }}>
        <AlertTitle>{t(label ?? 'Organizations restriction')}</AlertTitle>
        <Field
          component={AutocompleteField}
          name={name}
          multiple={true}
          disabled={disabled}
          style={{ width: '100%', marginTop: 10 }}
          textfieldprops={{
            variant: 'standard',
            helperText: helpertext,
            fullWidth: true,
            onFocus: this.searchOrganizations.bind(this),
          }}
          noOptionsText={t('No available options')}
          options={this.state.organizations}
          onInputChange={this.searchOrganizations.bind(this)}
          onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
          renderOption={(props, option) => (
            <li {...props}>
              <div className={classes.icon} style={{ color: option.color }}>
                <AccountBalanceOutlined />
              </div>
              <div className={classes.text}>{option.label}</div>
            </li>
          )}
        />
      </Alert>
    );
  }
}

export default compose(inject18n, withStyles(styles))(ObjectOrganizationField);
