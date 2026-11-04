import React, { useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import { styled } from '@mui/material/styles';
import { fetchQuery } from '../../../../relay/environment';
import ComboboxField from '../../../../components/ComboboxField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';

const OptionIcon = styled('div')({
  paddingTop: 4,
  display: 'inline-block',
});

const OptionText = styled('div')({
  display: 'inline-block',
  flexGrow: 1,
  marginLeft: 10,
});

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
            <OptionIcon>
              <ItemIcon type="Organization" />
            </OptionIcon>
            <OptionText>{option.label}</OptionText>
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
          <OptionIcon>
            <ItemIcon type="Organization" />
          </OptionIcon>
          <OptionText>{option.label}</OptionText>
        </>
      )}
    />
  );
  if (!alert) {
    return FieldElement;
  }
  return (
    <>
      <Alert severity="warning" variant="outlined" style={style}>
        <AlertTitle>{t_i18n('Organizations restriction')}</AlertTitle>
      </Alert>
      <div style={{ marginTop: 16 }}>{FieldElement}</div>
    </>
  );
};

export default ObjectOrganizationField;
