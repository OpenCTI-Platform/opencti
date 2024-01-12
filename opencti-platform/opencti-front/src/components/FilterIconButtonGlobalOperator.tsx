import React, { FunctionComponent } from 'react';
import { useFormatter } from './i18n';

interface FilterIconButtonGlobalOperatorProps {
  classOperator: string;
  globalMode: string;
  handleSwitchGlobalMode?: () => void;
}
const FilterIconButtonGlobalOperator: FunctionComponent<
FilterIconButtonGlobalOperatorProps
> = ({
  classOperator,
  globalMode,
  handleSwitchGlobalMode,
}) => {
  const { t } = useFormatter();
  return (
    <div className={classOperator} onClick={handleSwitchGlobalMode}>
      {t(globalMode.toUpperCase())}
    </div>
  );
};

export default FilterIconButtonGlobalOperator;
