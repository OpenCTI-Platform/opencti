import { useGraphContext } from './GraphContext';

const useGraphToolbar = () => {
  const { graphState, setGraphProp } = useGraphContext();
  const {
    mode3D,
    modeTree,
    withForces,
    selectFreeRectangle,
    selectFree,
    selectRelationshipMode,
    showTimeRange,
  } = graphState;

  const toggleMode3D = () => {
    setGraphProp('mode3D', !mode3D);
  };

  const toggleVerticalTree = () => {
    setGraphProp('modeTree', modeTree !== 'vertical' ? 'vertical' : null);
  };

  const toggleHorizontalTree = () => {
    setGraphProp('modeTree', modeTree !== 'horizontal' ? 'horizontal' : null);
  };

  const toggleForces = () => {
    setGraphProp('withForces', !withForces);
  };

  const toggleSelectFreeRectangle = () => {
    setGraphProp('selectFreeRectangle', !selectFreeRectangle);
  };

  const toggleSelectFree = () => {
    setGraphProp('selectFree', !selectFree);
  };

  const switchSelectRelationshipMode = () => {
    if (selectRelationshipMode === 'children') setGraphProp('selectRelationshipMode', 'parent');
    else if (selectRelationshipMode === 'parent') setGraphProp('selectRelationshipMode', 'deselect');
    else if (selectRelationshipMode === 'deselect') setGraphProp('selectRelationshipMode', null);
    else if (selectRelationshipMode === null) setGraphProp('selectRelationshipMode', 'children');
  };

  const toggleTimeRange = () => {
    setGraphProp('showTimeRange', !showTimeRange);
  };

  return {
    toggleMode3D,
    toggleVerticalTree,
    toggleHorizontalTree,
    toggleForces,
    toggleSelectFreeRectangle,
    toggleSelectFree,
    switchSelectRelationshipMode,
    toggleTimeRange,
  };
};

export default useGraphToolbar;
