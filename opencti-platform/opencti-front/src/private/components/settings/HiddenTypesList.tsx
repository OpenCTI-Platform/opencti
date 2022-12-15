import MenuItem from '@mui/material/MenuItem';
import Checkbox from '@mui/material/Checkbox';
import React, { FunctionComponent } from 'react';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import { Field, FormikValues } from 'formik';
import { useFormatter } from '../../../components/i18n';
import SelectField from '../../../components/SelectField';
import { SubscriptionFocus } from '../../../components/Subscription';

interface HiddenTypesListProps {
  values: FormikValues,
  handleChangeFocus: (id: string, name: string) => void,
  handleSubmitField: (id: string, name: string, value: string[]) => void,
  id: string,
  editContext: { name: string, focusOn: string },
}

const HiddenTypesList: FunctionComponent<HiddenTypesListProps> = ({
  values,
  handleChangeFocus,
  handleSubmitField,
  id,
  editContext,
}) => {
  const { t } = useFormatter();

  const platform_hidden_types = values.platform_hidden_types ?? [];

  return (
    <Field
      component={SelectField}
      variant="standard"
      name="platform_hidden_types"
      label={t('Hidden entity types')}
      fullWidth={true}
      multiple={true}
      containerstyle={{
        marginTop: 20,
        width: '100%',
      }}
      onFocus={(name: string) => handleChangeFocus(id, name)}
      onChange={(name: string, value: string[]) => handleSubmitField(id, name, value)}
      helpertext={
        <SubscriptionFocus
          context={editContext}
          fieldName="platform_hidden_types"
        />
      }
      renderValue={(selected: string[]) => (
        <Box
          sx={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 0.5,
          }}
        >
          {selected.map((value) => (
            <Chip
              key={value}
              label={t(`entity_${value}`)}
            />
          ))}
        </Box>
      )}
    >
      <MenuItem value="Threats" dense={true}>
        <Checkbox
          checked={platform_hidden_types.includes('Threats')}
        />
        {t('Threats')}
      </MenuItem>
      <MenuItem
        value="Threat-Actor"
        disabled={platform_hidden_types.includes('Threats')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Threat-Actor')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Threat-Actor')}
      </MenuItem>
      <MenuItem
        value="Intrusion-Set"
        disabled={platform_hidden_types.includes('Threats')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Intrusion-Set')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Intrusion-Set')}
      </MenuItem>
      <MenuItem
        value="Campaign"
        disabled={platform_hidden_types.includes('Threats')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Campaign')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Campaign')}
      </MenuItem>
      <MenuItem value="Arsenal" dense={true}>
        <Checkbox
          checked={platform_hidden_types.includes('Arsenal')}
        />
        {t('Arsenal')}
      </MenuItem>
      <MenuItem
        value="Malware"
        disabled={platform_hidden_types.includes('Arsenal')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Malware')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Malware')}
      </MenuItem>
      <MenuItem
        value="Channel"
        disabled={platform_hidden_types.includes('Arsenal')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Channel')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Channel')}
      </MenuItem>
      <MenuItem
        value="Tool"
        disabled={platform_hidden_types.includes('Arsenal')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Tool')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Tool')}
      </MenuItem>
      <MenuItem
        value="Vulnerability"
        disabled={platform_hidden_types.includes('Arsenal')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Vulnerability')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Vulnerability')}
      </MenuItem>
      <MenuItem value="Techniques" dense={true}>
        <Checkbox
          checked={platform_hidden_types.includes('Techniques')}
        />
        {t('Techniques')}
      </MenuItem>
      <MenuItem
        value="Attack-Pattern"
        disabled={platform_hidden_types.includes('Techniques')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Attack-Pattern')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Attack-Pattern')}
      </MenuItem>
      <MenuItem
        value="Narrative"
        disabled={platform_hidden_types.includes('Techniques')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Narrative')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Narrative')}
      </MenuItem>
      <MenuItem
        value="Course-Of-Action"
        disabled={platform_hidden_types.includes('Techniques')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Course-Of-Action')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Course-Of-Action')}
      </MenuItem>
      <MenuItem
        value="Data-Component"
        disabled={platform_hidden_types.includes('Techniques')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Data-Component')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Data-Component')}
      </MenuItem>
      <MenuItem
        value="Data-Source"
        disabled={platform_hidden_types.includes('Techniques')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Data-Source')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Data-Source')}
      </MenuItem>
      <MenuItem value="Entities" dense={true}>
        <Checkbox
          checked={platform_hidden_types.includes('Entities')}
        />
        {t('Entities')}
      </MenuItem>
      <MenuItem
        value="Sector"
        disabled={platform_hidden_types.includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Sector')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Sector')}
      </MenuItem>
      <MenuItem
        value="Event"
        disabled={platform_hidden_types.includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Event')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Event')}
      </MenuItem>
      <MenuItem
        value="Organization"
        disabled={platform_hidden_types.includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Organization')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Organization')}
      </MenuItem>
      <MenuItem
        value="System"
        disabled={platform_hidden_types.includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('System')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_System')}
      </MenuItem>
      <MenuItem
        value="Individual"
        disabled={platform_hidden_types.includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Individual')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Individual')}
      </MenuItem>
      <MenuItem value="Locations" dense={true}>
        <Checkbox
          checked={platform_hidden_types.includes('Locations')}
        />
        {t('Locations')}
      </MenuItem>
      <MenuItem
        value="Region"
        disabled={platform_hidden_types.includes('Locations')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Region')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Region')}
      </MenuItem>
      <MenuItem
        value="Country"
        disabled={platform_hidden_types.includes('Locations')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Country')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Country')}
      </MenuItem>
      <MenuItem
        value="City"
        disabled={platform_hidden_types.includes('Locations')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('City')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_City')}
      </MenuItem>
      <MenuItem
        value="Position"
        disabled={platform_hidden_types.includes('Locations')}
        dense={true}
      >
        <Checkbox
          checked={platform_hidden_types.includes('Position')}
          style={{ marginLeft: 10 }}
        />
        {t('entity_Position')}
      </MenuItem>
    </Field>
  );
};

export default HiddenTypesList;
