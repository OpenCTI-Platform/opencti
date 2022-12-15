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

  const platformEntitiesAutoRef = values.platform_entities_files_ref ?? [];
  return (
    <Field
      component={SelectField}
      variant="standard"
      name="platform_entities_files_ref"
      label={t('Entities automatic reference from files')}
      fullWidth={true}
      multiple={true}
      containerstyle={{ marginTop: 20, width: '100%' }}
      onFocus={(name: string) => handleChangeFocus(id, name)}
      onChange={(name: string, value: string[]) => handleSubmitField(id, name, value)}
      helpertext={
        <SubscriptionFocus context={editContext} fieldName="platform_entities_files_ref" />
      }
      renderValue={(selected: string[]) => (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
          {selected.map((value) => (
            <Chip key={value} label={t(`entity_${value}`)} />
          ))}
        </Box>
      )}>
      <MenuItem value="Artifact" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Artifact')} />
        {t('entity_Artifact')}
      </MenuItem>
      <MenuItem value="Attack-Pattern" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Attack-Pattern')} />
        {t('entity_Attack-Pattern')}
      </MenuItem>
      <MenuItem value="Campaign" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Campaign')} />
        {t('entity_Campaign')}
      </MenuItem>
      <MenuItem value="Channel" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Channel')} />
        {t('entity_Channel')}
      </MenuItem>
      <MenuItem value="City" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('City')} />
        {t('entity_City')}
      </MenuItem>
      <MenuItem value="Country" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Country')} />
        {t('entity_Country')}
      </MenuItem>
      <MenuItem value="Course-Of-Action" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Course-Of-Action')} />
        {t('entity_Course-Of-Action')}
      </MenuItem>
      <MenuItem value="Event" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Event')} />
        {t('entity_Event')}
      </MenuItem>
      <MenuItem value="Grouping" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Grouping')} />
        {t('entity_Grouping')}
      </MenuItem>
      <MenuItem value="Incident" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Incident')} />
        {t('entity_Incident')}
      </MenuItem>
      <MenuItem value="Indicator" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Indicator')} />
        {t('entity_Indicator')}
      </MenuItem>
      <MenuItem value="Individual" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Individual')} />
        {t('entity_Individual')}
      </MenuItem>
      <MenuItem value="Infrastructure" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Infrastructure')} />
        {t('entity_Infrastructure')}
      </MenuItem>
      <MenuItem value="Intrusion-Set" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Intrusion-Set')} />
        {t('entity_Intrusion-Set')}
      </MenuItem>
      <MenuItem value="Malware" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Malware')} />
        {t('entity_Malware')}
      </MenuItem>
      <MenuItem value="Narrative" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Narrative')} />
        {t('entity_Narrative')}
      </MenuItem>
      <MenuItem value="Note" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Note')} />
        {t('entity_Note')}
      </MenuItem>
      <MenuItem value="Observable" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Observable')} />
        {t('entity_Observable')}
      </MenuItem>
      <MenuItem value="Observed-Data" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Observed-Data')} />
        {t('entity_Observed-Data')}
      </MenuItem>
      <MenuItem value="Opinion" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Opinion')} />
        {t('entity_Opinion')}
      </MenuItem>
      <MenuItem value="Organization" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Organization')} />
        {t('entity_Organization')}
      </MenuItem>
      <MenuItem value="Position" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Position')} />
        {t('entity_Position')}
      </MenuItem>
      <MenuItem value="Report" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Report')} />
        {t('entity_Report')}
      </MenuItem>
      <MenuItem value="Sector" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Sector')} />
        {t('entity_Sector')}
      </MenuItem>
      <MenuItem value="Sighting" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Sighting')} />
        {t('entity_Sighting')}
      </MenuItem>
      <MenuItem value="System" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('System')} />
        {t('entity_System')}
      </MenuItem>
      <MenuItem value="Threat-Actor" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Threat-Actor')} />
        {t('entity_Threat-Actor')}
      </MenuItem>
      <MenuItem value="Tool" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Tool')} />
        {t('entity_Tool')}
      </MenuItem>
      <MenuItem value="Vulnerability" dense={true}>
        <Checkbox checked={platformEntitiesAutoRef.includes('Vulnerability')} />
        {t('entity_Vulnerability')}
      </MenuItem>
    </Field>
  );
};

export default AutomaticTypesList;
