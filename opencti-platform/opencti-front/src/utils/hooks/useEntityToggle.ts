import { React } from 'mdi-material-ui';
import * as R from 'ramda';
import { useState } from 'react';

const useEntityToggle = <T extends { id: string }>(key: string) => {
  const { numberOfElements } = JSON.parse(window.localStorage.getItem(key) ?? '');

  const [selectedElements, setSelectedElements] = useState<Record<string, T>>({});
  const [deSelectedElements, setDeSelectedElements] = useState<Record<string, T>>({});
  const [selectAll, setSelectAll] = useState(false);

  const onToggleEntity = (entity: T, event: React.SyntheticEvent) => {
    event.stopPropagation();
    event.preventDefault();
    if (entity.id in (selectedElements || {})) {
      const newSelectedElements = R.omit([entity.id], selectedElements);
      setSelectAll(false);
      setSelectedElements(newSelectedElements);
    } else if (selectAll && entity.id in (deSelectedElements || {})) {
      const newDeSelectedElements = R.omit([entity.id], deSelectedElements);
      setDeSelectedElements(newDeSelectedElements);
    } else if (selectAll) {
      const newDeSelectedElements = {
        ...deSelectedElements,
        [entity.id]: entity,
      };
      setDeSelectedElements(newDeSelectedElements);
    } else {
      const newSelectedElements = {
        ...selectedElements,
        [entity.id]: entity,
      };
      setSelectAll(false);
      setSelectedElements(newSelectedElements);
    }
  };

  const handleToggleSelectAll = () => {
    setSelectAll(!selectAll);
    setSelectedElements({});
    setDeSelectedElements({});
  };

  const handleClearSelectedElements = () => {
    setSelectAll(false);
    setSelectedElements({});
    setDeSelectedElements({});
  };

  let numberOfSelectedElements = Object.keys(selectedElements).length;
  if (selectAll) {
    numberOfSelectedElements = (numberOfElements?.original ?? 0)
      - Object.keys(deSelectedElements).length;
  }
  return {
    onToggleEntity,
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    numberOfSelectedElements,
  };
};

export default useEntityToggle;
