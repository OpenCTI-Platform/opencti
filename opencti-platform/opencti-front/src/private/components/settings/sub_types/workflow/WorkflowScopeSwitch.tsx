import { Button } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import type { WorkflowScope } from '../SubTypeWorkflow';

interface WorkflowScopeSwitchProps {
  scope: WorkflowScope;
  onScopeChange: (scope: WorkflowScope) => void;
}

// FDS-WORKAROUND (LIBRARY-FEEDBACK #63): ButtonGroupItem is a glyph-only square, so a segmented
// control whose segments carry a text label is a radio group of two Buttons: the selected scope is
// the primary one.
const WorkflowScopeSwitch = ({ scope, onScopeChange }: WorkflowScopeSwitchProps) => {
  const { t_i18n } = useFormatter();

  const scopes: { value: WorkflowScope; label: string }[] = [
    { value: 'GLOBAL', label: t_i18n('Global') },
    { value: 'REQUEST_ACCESS', label: t_i18n('Request access') },
  ];

  return (
    <div role="radiogroup" aria-label={t_i18n('Workflow scope')} style={{ display: 'flex', gap: 8 }}>
      {scopes.map(({ value, label }) => {
        const selected = value === scope;
        return (
          <Button
            key={value}
            role="radio"
            aria-checked={selected}
            size="md"
            priority={selected ? 'primary' : 'secondary'}
            onClick={() => {
              if (!selected) onScopeChange(value);
            }}
          >
            {label}
          </Button>
        );
      })}
    </div>
  );
};

export default WorkflowScopeSwitch;
