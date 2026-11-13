import { Field, Form, Formik } from 'formik';
import SwitchField from '../fields/SwitchField';
import { useFormatter } from '../i18n';
import type { DashboardConfig } from './dashboard-types';

export type ViewerPermissions = Pick<DashboardConfig, 'allowViewersToEditTimeFilters' | 'allowViewersToChangeVariables'>;
type ViewerPermission = keyof ViewerPermissions;

interface DashboardViewerPermissionsProps {
  config: DashboardConfig;
  // The switches whose change is being saved: shown disabled.
  pending?: readonly ViewerPermission[];
  // Reports the switched key only: the caller merges it into the dashboard config.
  onChange: (patch: ViewerPermissions) => void;
}

/**
 * What a viewer of the dashboard may change for themselves. None of these grants any right to write the dashboard.
 * Open unless the editor closed them: a dashboard without the keys lets its viewers change everything for themselves.
 * Laid out as the other switches of the edition drawers; each one follows the given config, not the form state.
 */
const DashboardViewerPermissions = ({ config, pending = [], onChange }: DashboardViewerPermissionsProps) => {
  const { t_i18n } = useFormatter();
  const isOn = (name: ViewerPermission) => config[name] !== false;
  const handleChange = (name: ViewerPermission, value: string) => onChange({ [name]: value === 'true' });
  return (
    <Formik
      enableReinitialize
      initialValues={{ allowViewersToEditTimeFilters: isOn('allowViewersToEditTimeFilters'), allowViewersToChangeVariables: isOn('allowViewersToChangeVariables') }}
      onSubmit={() => {}}
    >
      <Form>
        <Field
          component={SwitchField}
          type="checkbox"
          name="allowViewersToEditTimeFilters"
          label={t_i18n('Allow viewers to edit time filters')}
          checked={isOn('allowViewersToEditTimeFilters')}
          disabled={pending.includes('allowViewersToEditTimeFilters')}
          containerstyle={{ marginTop: 20 }}
          onChange={handleChange}
        />
        <Field
          component={SwitchField}
          type="checkbox"
          name="allowViewersToChangeVariables"
          label={t_i18n('Allow viewers to change variable values')}
          checked={isOn('allowViewersToChangeVariables')}
          disabled={pending.includes('allowViewersToChangeVariables')}
          containerstyle={{ marginTop: 20 }}
          onChange={handleChange}
        />
      </Form>
    </Formik>
  );
};

export default DashboardViewerPermissions;
