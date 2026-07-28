import React, { createContext, ReactNode, useContext, useEffect, useMemo, useState } from 'react';

export interface DashboardVariableRef {
  id: string;
  name: string;
  filterKey: string;
  filterKeyType: string;
  defaultValue?: string | null;
}

interface DashboardVariablesContextType {
  variables: ReadonlyArray<DashboardVariableRef>;
  /** Raw user state map persisted in workspace user state (includes metadata like __enabled__). */
  rawVariableValues: Record<string, string>;
  /** Current runtime value for each variable (variableId → value). */
  variableValues: Record<string, string>;
  setVariableValue: (variableId: string, value: string | null | undefined) => void;
  setVariableValues: (values: Record<string, string>) => void;
}

const DashboardVariablesContext = createContext<DashboardVariablesContextType>({
  variables: [],
  rawVariableValues: {},
  variableValues: {},
  setVariableValue: () => {},
  setVariableValues: () => {},
});

export const DashboardVariablesProvider = ({
  children,
  variables,
  initialVariableValues = {},
}: {
  children: ReactNode;
  variables: ReadonlyArray<DashboardVariableRef>;
  initialVariableValues?: Record<string, string>;
}) => {
  const ENABLED_PREFIX = '__enabled__:';
  const [overrides, setOverrides] = useState<Record<string, string>>(initialVariableValues);

  useEffect(() => {
    setOverrides(initialVariableValues);
  }, [initialVariableValues]);

  const variableValues = useMemo(() => {
    const disabledVariableIds = new Set(
      Object.entries(overrides)
        .filter(([key, value]) => key.startsWith(ENABLED_PREFIX) && value === 'false')
        .map(([key]) => key.slice(ENABLED_PREFIX.length)),
    );

    const mergedValues: Record<string, string> = {};
    variables.forEach((variable) => {
      if (disabledVariableIds.has(variable.id)) {
        return;
      }

      const overrideValue = overrides[variable.id];
      if (typeof overrideValue === 'string' && overrideValue.length > 0) {
        mergedValues[variable.id] = overrideValue;
        return;
      }

      const defaultValue = variable.defaultValue ?? '';
      if (defaultValue.length > 0) {
        mergedValues[variable.id] = defaultValue;
      }
    });

    return mergedValues;
  }, [variables, overrides]);

  const setVariableValue = (variableId: string, value: string | null | undefined) => {
    setOverrides((prev) => {
      if (!value) {
        const { [variableId]: _, ...rest } = prev;
        return rest;
      }
      return { ...prev, [variableId]: value };
    });
  };

  const setVariableValues = (values: Record<string, string>) => {
    setOverrides(values);
  };

  return (
    <DashboardVariablesContext.Provider
      value={{
        variables,
        rawVariableValues: overrides,
        variableValues,
        setVariableValue,
        setVariableValues,
      }}
    >
      {children}
    </DashboardVariablesContext.Provider>
  );
};

export const useDashboardVariables = () => useContext(DashboardVariablesContext);
