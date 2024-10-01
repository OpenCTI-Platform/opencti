import { TableTuneIcon } from 'filigran-icon';
import React from 'react';
import NestedMenuButton from '../../nestedMenu/NestedMenuButton';
import { useDataTableContext } from '../dataTableUtils';
import { LocalStorageColumns } from '../dataTableTypes';
import { useFormatter } from '../../i18n';

const ResetColumnsButton = () => {
  const { t_i18n } = useFormatter();
  const {
    storageKey,
    resetColumns,
    useDataTableLocalStorage,
  } = useDataTableContext();

  const [_, setLocalStorageColumns] = useDataTableLocalStorage<LocalStorageColumns>(`${storageKey}_columns`, {}, true, true);

  const resetTable = () => {
    setLocalStorageColumns({});
    resetColumns();
  };
  const nestedMenuOptions = [
    {
      value: 'menu-reset',
      label: t_i18n('Reset table'),
      onClick: () => resetTable(),
      menuLevel: 0,
    },
  ];

  return (
    <div>
      <NestedMenuButton
        menuButtonProps={{
          variant: 'outlined',
          size: 'small',
          color: 'pagination',
          style: {
            padding: 6,
            minWidth: 36,
            border: 'none',
          },
        }}
        menuButtonChildren={<TableTuneIcon />}
        options={nestedMenuOptions}
        menuLevels={2}
      />
    </div>
  );
};

export default ResetColumnsButton;
