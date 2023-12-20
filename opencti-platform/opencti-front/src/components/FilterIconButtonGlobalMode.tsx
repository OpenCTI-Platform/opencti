import React, { FunctionComponent } from 'react';
import { useFormatter } from './i18n';

interface FilterIconButtonGlobalModeProps {
  classOperator: string;
  globalMode: string;
  handleSwitchGlobalMode?: () => void;
}
const FilterIconButtonGlobalMode: FunctionComponent<
FilterIconButtonGlobalModeProps
> = ({
  classOperator,
  globalMode,
  handleSwitchGlobalMode,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <div className={classOperator} onClick={handleSwitchGlobalMode}>
      {t_i18n(globalMode.toUpperCase())}
    </div>
  );
};

export default FilterIconButtonGlobalMode;
