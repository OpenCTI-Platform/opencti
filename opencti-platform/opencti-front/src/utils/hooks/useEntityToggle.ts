import React, { useCallback, useState } from 'react';
import * as R from 'ramda';
import useBus from './useBus';

export interface UseEntityToggle<T> {
  selectedElements: Record<string, T>;
  deSelectedElements: Record<string, T>;
  selectAll: boolean;
  numberOfSelectedElements: number;
  onToggleEntity: (
    entity: T | T[],
    _?: React.SyntheticEvent,
    forceRemove?: T[]
  ) => void;
  handleClearSelectedElements: () => void;
  handleToggleSelectAll: () => void;
  setSelectedElements: (selectedElements: Record<string, T>) => void;
}

type UseEntityToggleType = {
  id: string,
  name?: string | null,
  entity_type?: string | null
};

const useEntityToggle = <T extends UseEntityToggleType>(
  key: string,
): UseEntityToggle<T> => {
  const { numberOfElements } = JSON.parse(window.localStorage.getItem(key) ?? '{}');

  const [selectAll, setSelectAll] = useState(false);
  const [selectedElements, setSelectedElements] = useState<Record<string, T>>({});
  const [deSelectedElements, setDeSelectedElements] = useState<Record<string, T>>({});

  const busKey = `${key}_entityToggle`;
  const callback = useCallback((values: {
    selectAll?: boolean,
    selectedElements?: Record<string, T>,
    deSelectedElements?: Record<string, T>,
  }) => {
    if (values.selectAll != null) {
      setSelectAll(values.selectAll);
    }
    if (values.selectedElements != null) {
      setSelectedElements(values.selectedElements);
    }
    if (values.deSelectedElements != null) {
      setDeSelectedElements(values.deSelectedElements);
    }
  }, []);
  const dispatch = useBus(busKey, callback);

  const onToggleEntity = (
    entity: T | T[],
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
      let newSelectedElements: Record<string, T> = {
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
        ) as Record<string, T>;
      }
      setSelectAll(false);
      setSelectedElements(newSelectedElements);
      setDeSelectedElements({});
      dispatch(busKey, { selectAll: false, selectedElements: newSelectedElements, deSelectedElements: {} });
    } else if (entity.id in (selectedElements || {})) {
      const newSelectedElements = R.omit([entity.id], selectedElements);
      setSelectAll(false);
      setSelectedElements(newSelectedElements);
      dispatch(busKey, { selectAll: false, selectedElements: newSelectedElements });
    } else if (selectAll && entity.id in (deSelectedElements || {})) {
      const newDeSelectedElements = R.omit([entity.id], deSelectedElements);
      setDeSelectedElements(newDeSelectedElements);
      dispatch(busKey, { deSelectedElements: newDeSelectedElements });
    } else if (selectAll) {
      const newDeSelectedElements = {
        ...deSelectedElements,
        [entity.id]: entity,
      };
      setDeSelectedElements(newDeSelectedElements);
      dispatch(busKey, { deSelectedElements: newDeSelectedElements });
    } else {
      const newSelectedElements = {
        ...selectedElements,
        [entity.id]: entity,
      };
      setSelectAll(false);
      setSelectedElements(newSelectedElements);
      dispatch(busKey, { selectAll: false, selectedElements: newSelectedElements });
    }
  };

  const handleToggleSelectAll = () => {
    setSelectAll(!selectAll);
    setSelectedElements({});
    setDeSelectedElements({});
    dispatch(busKey, { selectAll: !selectAll, selectedElements: {}, deSelectedElements: {} });
  };

  const handleClearSelectedElements = () => {
    setSelectAll(false);
    setSelectedElements({});
    setDeSelectedElements({});
    dispatch(busKey, { selectAll: false, selectedElements: {}, deSelectedElements: {} });
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
