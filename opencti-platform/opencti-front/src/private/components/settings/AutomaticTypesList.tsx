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
      <MenuItem value="Analysis" dense={true}>
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Analysis') > -1
          }
        />
        {t('Analysis')}
      </MenuItem>
      <MenuItem
        value="Report"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Analysis')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Report') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Report')}
      </MenuItem>
      <MenuItem
        value="Grouping"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Analysis')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Grouping') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Grouping')}
      </MenuItem>
      <MenuItem
        value="Note"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Analysis')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Note') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Note')}
      </MenuItem>
      <MenuItem
        value="Opinion"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Analysis')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Opinion') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Opinion')}
      </MenuItem>
      <MenuItem value="Events" dense={true}>
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Events') > -1
          }
        />
        {t('Events')}
      </MenuItem>
      <MenuItem
        value="Incident"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Events')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Incident') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Incident')}
      </MenuItem>
      <MenuItem
        value="Sighting"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Events')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Sighting') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Sighting')}
      </MenuItem>
      <MenuItem
        value="Observed-Data"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Events')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Observed-Data') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Observed-Data')}
      </MenuItem>
      <MenuItem value="Observations" dense={true}>
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Observations') > -1
          }
        />
        {t('Observations')}
      </MenuItem>
      <MenuItem
        value="Observable"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Observations')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Observable') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Observable')}
      </MenuItem>
      <MenuItem
        value="Artifact"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Observations')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Artifact') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Artifact')}
      </MenuItem>
      <MenuItem
        value="Indicator"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Observations')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Indicator') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Indicator')}
      </MenuItem>
      <MenuItem
        value="Infrastructure"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Observations')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Infrastructure') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Infrastructure')}
      </MenuItem>
      <MenuItem value="Threats" dense={true}>
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Threats') > -1
          }
        />
        {t('Threats')}
      </MenuItem>
      <MenuItem
        value="Threat-Actor"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Threats')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Threat-Actor') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Threat-Actor')}
      </MenuItem>
      <MenuItem
        value="Intrusion-Set"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Threats')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Intrusion-Set') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Intrusion-Set')}
      </MenuItem>
      <MenuItem
        value="Campaign"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Threats')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Campaign') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Campaign')}
      </MenuItem>
      <MenuItem value="Arsenal" dense={true}>
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Arsenal') > -1
          }
        />
        {t('Arsenal')}
      </MenuItem>
      <MenuItem
        value="Malware"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Arsenal')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Malware') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Malware')}
      </MenuItem>
      <MenuItem
        value="Attack-Pattern"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Arsenal')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Attack-Pattern') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Attack-Pattern')}
      </MenuItem>
      <MenuItem
        value="Channel"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Arsenal')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Channel') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Channel')}
      </MenuItem>
      <MenuItem
        value="Narrative"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Arsenal')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Narrative') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Narrative')}
      </MenuItem>
      <MenuItem
        value="Course-Of-Action"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Arsenal')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Course-Of-Action') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Course-Of-Action')}
      </MenuItem>
      <MenuItem
        value="Tool"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Arsenal')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Tool') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Tool')}
      </MenuItem>
      <MenuItem
        value="Vulnerability"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Arsenal')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Vulnerability') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Vulnerability')}
      </MenuItem>
      <MenuItem value="Entities" dense={true}>
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Entities') > -1
          }
        />
        {t('Entities')}
      </MenuItem>
      <MenuItem
        value="Sector"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Sector') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Sector')}
      </MenuItem>
      <MenuItem
        value="Country"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Country') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Country')}
      </MenuItem>
      <MenuItem
        value="City"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('City') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_City')}
      </MenuItem>
      <MenuItem
        value="Position"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Position') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Position')}
      </MenuItem>
      <MenuItem
        value="Event"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Event') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Event')}
      </MenuItem>
      <MenuItem
        value="Organization"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Organization') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Organization')}
      </MenuItem>
      <MenuItem
        value="System"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('System') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_System')}
      </MenuItem>
      <MenuItem
        value="Individual"
        disabled={(
          values.platform_automatic_types || []
        ).includes('Entities')}
        dense={true}
      >
        <Checkbox
          checked={
            (
              values.platform_automatic_types || []
            ).indexOf('Individual') > -1
          }
          style={{ marginLeft: 10 }}
        />
        {t('entity_Individual')}
      </MenuItem>
    </Field>
  );
};

export default AutomaticTypesList;
