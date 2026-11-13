import React from 'react';
import { Field } from 'formik';
import SelectFieldFds, { SelectItem } from '../../../components/fields/SelectFieldFds';
import { useFormatter } from '../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import { HUNT_DOCS, type HuntIncidentModeValue } from './hunt-utils';
import { HuntHelp } from './HuntLearnMore';

/** How an escalating run of the hunt opens its incident: as a draft an analyst validates, or directly in the knowledge. */
const HuntIncidentModeField = ({ mode }: { mode: HuntIncidentModeValue }) => {
  const { t_i18n } = useFormatter();
  const help = mode === 'incident'
    ? t_i18n('The incident is created in the knowledge at once, without review: keep it for hunts whose hits always call for a response.')
    : t_i18n('The incident opens in a draft workspace: a user with the Delete knowledge capability reviews and validates it.');
  return (
    <div style={fieldSpacingContainerStyle} data-testid="hunt-incident-mode">
      <Field
        component={SelectFieldFds}
        name="hunt_incident_mode"
        label={t_i18n('Incident')}
        fullWidth
        helpertext={<HuntHelp text={help} href={HUNT_DOCS.incident} />}
      >
        <SelectItem value="draft">{t_i18n('Open the incident as a draft')}</SelectItem>
        <SelectItem value="incident">{t_i18n('Create the incident directly')}</SelectItem>
      </Field>
    </div>
  );
};

export default HuntIncidentModeField;
