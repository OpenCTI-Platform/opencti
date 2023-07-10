import React, { useState } from 'react';
import * as R from 'ramda';

export interface UseEntityToggle<T> {
  selectedElements: Record<string, T>;
  deSelectedElements: Record<string, T>;
  selectAll: boolean;
  numberOfSelectedElements: number;
  onToggleEntity: (
    entity: T,
    _?: React.SyntheticEvent,
    forceRemove?: T[]
  ) => void;
  handleClearSelectedElements: () => void;
  handleToggleSelectAll: () => void;
  setSelectedElements: (selectedElements: Record<string, T>) => void;
}

const useEntityToggle = <T extends { id: string }>(
  key: string,
): UseEntityToggle<T> => {
  const { numberOfElements } = JSON.parse(
    window.localStorage.getItem(key) ?? '{}',
  );
  const [selectedElements, setSelectedElements] = useState<Record<string, T>>(
    {},
  );
  const [deSelectedElements, setDeSelectedElements] = useState<
  Record<string, T>
  >({});
  const [selectAll, setSelectAll] = useState(false);
  const onToggleEntity = (
    entity: T,
    event?: React.SyntheticEvent,
    forceRemove: T[] = [],
  ) => {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (Array.isArray(entity)) {
      const currentIds = R.values(selectedElements).map((n) => n.id);
      const givenIds = entity.map((n) => n.id);
      const addedIds = givenIds.filter((n) => !currentIds.includes(n));
      let newSelectedElements = {
        ...selectedElements,
        ...R.indexBy(
          R.prop('id'),
          entity.filter((n) => addedIds.includes(n.id)),
        ),
      };
      if (forceRemove.length > 0) {
        newSelectedElements = R.omit(
          forceRemove.map((n) => n.id),
          newSelectedElements,
        );
      }
      setSelectAll(false);
      setSelectedElements(newSelectedElements);
      setDeSelectedElements({});
    } else if (entity.id in (selectedElements || {})) {
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
    setSelectedElements,
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    numberOfSelectedElements,
  };
};

export default useEntityToggle;
