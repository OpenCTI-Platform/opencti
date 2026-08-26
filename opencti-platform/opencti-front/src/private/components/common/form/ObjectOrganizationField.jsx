import React, { useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { makeStyles } from '@mui/styles';
import { fetchQuery } from '../../../../relay/environment';
import ComboboxField from '../../../../components/ComboboxField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
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

}));

export const searchObjectOrganizationFieldQuery = graphql`
  query ObjectOrganizationFieldQuery($search: String, $filters: FilterGroup) {
    organizations(orderBy: name, search: $search, filters: $filters) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const ObjectOrganizationField = (props) => {
  const {
    name,
    label,
    style,
    onChange,
    helpertext,
    disabled,
    defaultOrganizations,
    outlined = true,
    multiple = true,
    alert = true,
    filters = null,
  } = props;

  const defaultStateOrganizations = (defaultOrganizations ?? []).map((n) => ({
    label: n.name,
    value: n.id,
  }));
  const [organizations, setOrganizations] = useState(defaultStateOrganizations);
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const searchOrganizations = (search) => {
    fetchQuery(searchObjectOrganizationFieldQuery, {
      search,
      filters,
    })
      .toPromise()
      .then((data) => {
        const searchResults = data.organizations.edges.map((n) => ({
          label: n.node.name,
          value: n.node.id,
        }));
        setOrganizations(searchResults);
      });
  };

  if (outlined === false) {
    return (
      <Field
        component={ComboboxField}
        name={name}
        multiple={multiple}
        disabled={disabled}
        style={style}
        label={label ? t_i18n(label) : ''}
        helperText={helpertext}
        noOptionsText={t_i18n('No available options')}
        options={organizations}
        onInputChange={(search, meta) => {
          if (meta.cause === 'type') searchOrganizations(search);
        }}
        onFocusInput={() => searchOrganizations('')}
        onChange={typeof onChange === 'function' ? onChange : null}
        renderOption={(option) => (
          <>
            <div className={classes.icon}>
              <ItemIcon type="Organization" />
            </div>
            <div className={classes.text}>{option.label}</div>
          </>
        )}
      />
    );
  }
  const FieldElement = (
    <Field
      component={ComboboxField}
      // MUI hid its clear indicator here with display:none; the library defaults
      // clearable to true, so the affordance must be declined explicitly.
      clearable={false}
      name={name}
      multiple={multiple}
      style={style}
      disabled={disabled}
      label={t_i18n(label) ?? ''}
      helperText={helpertext}
      noOptionsText={t_i18n('No available options')}
      options={organizations}
      onInputChange={(search, meta) => {
        if (meta.cause === 'type') searchOrganizations(search);
      }}
      onFocusInput={() => searchOrganizations('')}
      onChange={typeof onChange === 'function' ? onChange : null}
      renderOption={(option) => (
        <>
          <div className={classes.icon}>
            <ItemIcon type="Organization" />
          </div>
          <div className={classes.text}>{option.label}</div>
        </>
      )}
    />
  );
  if (!alert) {
    return FieldElement;
  }
  return (
    <Alert
      severity="warning"
      variant="outlined"
      style={style}
      classes={{ message: classes.message }}
    >
      <AlertTitle>{t_i18n('Organizations restriction')}</AlertTitle>
      <div style={{ marginTop: 10 }}>{FieldElement}</div>
    </Alert>
  );
};

export default ObjectOrganizationField;
