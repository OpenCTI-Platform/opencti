import { ButtonGroup, ButtonGroupItem, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { FormTextbox, Variable } from 'mdi-material-ui';
import { FunctionComponent, ReactNode, useState } from 'react';
import { Filter } from '../../../utils/filters/filtersHelpers-types';
import { FilterDefinition } from '../../../utils/hooks/useAuth';
import type { DashboardVariable } from '../../dashboard/dashboard-types';
import { useOptionalDashboardVariableDefinitions } from '../../dashboard/DashboardVariablesContext';
import { isVariableCompatibleWithFilter } from '../../dashboard/dashboardVariablesCompatibility';
import { parseVariableToken, toVariableToken } from '../../dashboard/dashboardVariablesResolution';
import { useIsSubTypeOf } from '../../dashboard/useIsSubTypeOf';
import { useFormatter } from '../../i18n';
import { useFilterEditorContext } from './FilterEditorContext';

/**
 * Dashboard variables a value input with no option list (date, number, free text) can take.
 * `undefined` outside a dashboard with variables (no provider, feature off, home dashboard) and for a
 * sub key: the input then behaves exactly as anywhere else, a `$var:` looking value included.
 * Inside one, `compatibleVariables` is empty when no variable fits the filter or the host is not a workspace.
 */
export const useFilterValueVariables = (filterDefinition: FilterDefinition | undefined, subKey?: string) => {
  const variables = useOptionalDashboardVariableDefinitions();
  const { host } = useFilterEditorContext();
  const isSubTypeOf = useIsSubTypeOf();
  if (!variables || subKey) return undefined;
  const compatibleVariables = host?.kind === 'workspace'
    ? variables.filter((variable) => isVariableCompatibleWithFilter(variable, filterDefinition, { isSubTypeOf }))
    : [];
  return { compatibleVariables };
};

/** The values a fixed input may parse: in a dashboard, a variable token is never one of them (no `Invalid Date`, no `NaN`). */
export const withoutVariableTokens = (values: string[]) => values.filter((value) => parseVariableToken(value) === null);

type ValueSource = 'fixed' | 'variable';

// FDS-WORKAROUND (LIBRARY-FEEDBACK #63): a ButtonGroup item renders a glyph only, so each source is
// an icon named by its aria-label and its tooltip.
const GLYPH = { fontSize: 16 };

interface FilterValueVariableSwitchProps {
  filter?: Filter;
  /** Variables compatible with the filter, at least one. */
  variables: DashboardVariable[];
  /** The input of a fixed value, rendered unchanged in the fixed mode. */
  children: ReactNode;
}

/**
 * Lets a single value filter with no option list take either a fixed value (its usual input) or a
 * dashboard variable. Choosing a variable writes its token as the single value of the filter.
 */
const FilterValueVariableSwitch: FunctionComponent<FilterValueVariableSwitchProps> = ({
  filter,
  variables,
  children,
}) => {
  const { t_i18n } = useFormatter();
  const { helpers } = useFilterEditorContext();
  const currentToken = (filter?.values ?? []).find((value) => parseVariableToken(value) !== null);
  const [source, setSource] = useState<ValueSource>(currentToken ? 'variable' : 'fixed');
  const variableId = currentToken ? parseVariableToken(currentToken) : null;
  const isKnownVariable = variables.some(({ id }) => id === variableId);

  const handleSourceChange = (value: string) => {
    const nextSource = value as ValueSource;
    setSource(nextSource);
    // A token is never kept as a fixed value: the fixed input starts empty.
    if (nextSource === 'fixed' && currentToken) {
      helpers?.handleAddSingleValueFilter(filter?.id ?? '');
    }
  };

  const handleVariableChange = (id: string) => {
    // Stored as-is: the day shift of the fixed date input (lte / gt) is NOT applied to a variable,
    // the resolution substitutes the variable's stored ISO string at query time.
    helpers?.handleAddSingleValueFilter(filter?.id ?? '', toVariableToken(id));
  };

  const sources: { value: ValueSource; label: string; icon: ReactNode }[] = [
    { value: 'fixed', label: t_i18n('Fixed value'), icon: <FormTextbox sx={GLYPH} /> },
    { value: 'variable', label: t_i18n('Variable'), icon: <Variable sx={GLYPH} /> },
  ];

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <ButtonGroup size="md" value={source} onValueChange={handleSourceChange} aria-label={t_i18n('Value source')}>
        {sources.map(({ value, label, icon }) => (
          <Tooltip key={value}>
            <TooltipTrigger asChild>
              <ButtonGroupItem value={value} aria-label={label} icon={icon} />
            </TooltipTrigger>
            <TooltipContent>{label}</TooltipContent>
          </Tooltip>
        ))}
      </ButtonGroup>
      <div style={{ flex: 1, minWidth: 0 }}>
        {source === 'fixed'
          ? children
          : (
              <Select value={isKnownVariable && variableId ? variableId : ''} onValueChange={handleVariableChange}>
                <SelectTrigger className="w-full" aria-label={t_i18n('Variable')}>
                  <SelectValue placeholder={currentToken ? t_i18n('Deleted variable') : t_i18n('Select a variable')} />
                </SelectTrigger>
                <SelectContent aria-label={t_i18n('Variable')}>
                  {variables.map(({ id, name }) => (
                    <SelectItem key={id} value={id}>{name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
      </div>
    </div>
  );
};

export default FilterValueVariableSwitch;
