import MenuItem from '@mui/material/MenuItem';
import Checkbox from '@mui/material/Checkbox';
import React, { FunctionComponent } from 'react';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import { Field, FormikValues } from 'formik';
import { useFormatter } from '../../../components/i18n';
import SelectField from '../../../components/SelectField';
import { SubscriptionFocus } from '../../../components/Subscription';

interface AutomaticTypesListProps {
  values: FormikValues,
  handleChangeFocus: (id: string, name: string) => void,
  handleSubmitField: (id: string, name: string, value: string[]) => void,
  id: string,
  editContext: { name: string, focusOn: string },
}

const AutomaticTypesList: FunctionComponent<AutomaticTypesListProps> = ({ values, handleChangeFocus, handleSubmitField, id, editContext }) => {
  const { t } = useFormatter();

  return (
    <Field
      component={SelectField}
      variant="standard"
      name="platform_automatic_types"
      label={t('Automatic entity types')}
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
          fieldName="platform_automatic_types"
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
      <MenuItem
        value="Artifact"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Artifact') > -1
          }
        />
        {t('entity_Artifact')}
      </MenuItem>
      <MenuItem
        value="Attack-Pattern"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Attack-Pattern') > -1
          }
        />
        {t('entity_Attack-Pattern')}
      </MenuItem>
      <MenuItem
        value="Campaign"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Campaign') > -1
          }
        />
        {t('entity_Campaign')}
      </MenuItem>
      <MenuItem
        value="Channel"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Channel') > -1
          }
        />
        {t('entity_Channel')}
      </MenuItem>
      <MenuItem
        value="City"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('City') > -1
          }
        />
        {t('entity_City')}
      </MenuItem>
      <MenuItem
        value="Country"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Country') > -1
          }
        />
        {t('entity_Country')}
      </MenuItem>
      <MenuItem
        value="Course-Of-Action"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Course-Of-Action') > -1
          }
        />
        {t('entity_Course-Of-Action')}
      </MenuItem>
      <MenuItem
        value="Event"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Event') > -1
          }
        />
        {t('entity_Event')}
      </MenuItem>
      <MenuItem
        value="Grouping"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Grouping') > -1
          }
        />
        {t('entity_Grouping')}
      </MenuItem>
      <MenuItem
        value="Incident"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Incident') > -1
          }
        />
        {t('entity_Incident')}
      </MenuItem>
      <MenuItem
        value="Indicator"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Indicator') > -1
          }
        />
        {t('entity_Indicator')}
      </MenuItem>
      <MenuItem
        value="Individual"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Individual') > -1
          }
        />
        {t('entity_Individual')}
      </MenuItem>
      <MenuItem
        value="Infrastructure"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Infrastructure') > -1
          }
        />
        {t('entity_Infrastructure')}
      </MenuItem>
      <MenuItem
        value="Intrusion-Set"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Intrusion-Set') > -1
          }
        />
        {t('entity_Intrusion-Set')}
      </MenuItem>
      <MenuItem
        value="Malware"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Malware') > -1
          }
        />
        {t('entity_Malware')}
      </MenuItem>
      <MenuItem
        value="Narrative"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Narrative') > -1
          }
        />
        {t('entity_Narrative')}
      </MenuItem>
      <MenuItem
        value="Note"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Note') > -1
          }
        />
        {t('entity_Note')}
      </MenuItem>
      <MenuItem
        value="Observable"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Observable') > -1
          }
        />
        {t('entity_Observable')}
      </MenuItem>
      <MenuItem
        value="Observed-Data"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Observed-Data') > -1
          }
        />
        {t('entity_Observed-Data')}
      </MenuItem>
      <MenuItem
        value="Opinion"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Opinion') > -1
          }
        />
        {t('entity_Opinion')}
      </MenuItem>
      <MenuItem
        value="Organization"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Organization') > -1
          }
        />
        {t('entity_Organization')}
      </MenuItem>
      <MenuItem
        value="Position"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Position') > -1
          }
        />
        {t('entity_Position')}
      </MenuItem>
      <MenuItem
        value="Report"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Report') > -1
          }
        />
        {t('entity_Report')}
      </MenuItem>
      <MenuItem
        value="Sector"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Sector') > -1
          }
        />
        {t('entity_Sector')}
      </MenuItem>
      <MenuItem
        value="Sighting"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Sighting') > -1
          }
        />
        {t('entity_Sighting')}
      </MenuItem>
      <MenuItem
        value="System"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('System') > -1
          }
        />
        {t('entity_System')}
      </MenuItem>
      <MenuItem
        value="Threat-Actor"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Threat-Actor') > -1
          }
        />
        {t('entity_Threat-Actor')}
      </MenuItem>
      <MenuItem
        value="Tool"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Tool') > -1
          }
        />
        {t('entity_Tool')}
      </MenuItem>
      <MenuItem
        value="Vulnerability"
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Vulnerability') > -1
          }
        />
        {t('entity_Vulnerability')}
      </MenuItem>
    </Field>
  );
};

export default AutomaticTypesList;
