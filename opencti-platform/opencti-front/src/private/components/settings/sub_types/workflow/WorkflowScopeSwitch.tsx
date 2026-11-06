import { ButtonGroup, ButtonGroupItem, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { Earth, ShieldKeyOutline } from 'mdi-material-ui';
import { useFormatter } from '../../../../../components/i18n';
import type { WorkflowScope } from '../SubTypeWorkflow';

// FDS-WORKAROUND (LIBRARY-FEEDBACK #63): a ButtonGroup item renders a glyph only, so each scope is
// an icon named by its aria-label and its tooltip.
const GLYPH = { fontSize: 16 };

interface WorkflowScopeSwitchProps {
  scope: WorkflowScope;
  onScopeChange: (scope: WorkflowScope) => void;
}

const WorkflowScopeSwitch = ({ scope, onScopeChange }: WorkflowScopeSwitchProps) => {
  const { t_i18n } = useFormatter();

  const scopes: { value: WorkflowScope; label: string; icon: React.ReactNode }[] = [
    { value: 'GLOBAL', label: t_i18n('Global'), icon: <Earth sx={GLYPH} /> },
    { value: 'REQUEST_ACCESS', label: t_i18n('Request access workflow'), icon: <ShieldKeyOutline sx={GLYPH} /> },
  ];

  const handleValueChange = (value: string) => {
    // The group only ever emits one of its two scopes: this narrows the string to a scope.
    if (value !== 'GLOBAL' && value !== 'REQUEST_ACCESS') return;
    if (value !== scope) onScopeChange(value);
  };

  return (
    <ButtonGroup size="md" value={scope} onValueChange={handleValueChange} aria-label={t_i18n('Workflow scope')}>
      {scopes.map(({ value, label, icon }) => (
        <Tooltip key={value}>
          <TooltipTrigger asChild>
            <ButtonGroupItem value={value} aria-label={label} icon={icon} />
          </TooltipTrigger>
          <TooltipContent>{label}</TooltipContent>
        </Tooltip>
      ))}
    </ButtonGroup>
  );
};

export default WorkflowScopeSwitch;
