import { AutoFix, FamilyTree, Video3d } from 'mdi-material-ui';
import { AspectRatioOutlined, ScatterPlotOutlined } from '@mui/icons-material';
import React from 'react';
import GraphToolbarItem from './GraphToolbarItem';
import { useFormatter } from '../../../components/i18n';
import { useGraphContext } from '../utils/GraphContext';
import useGraphInteractions from '../utils/useGraphInteractions';

const GraphToolbarDisplayTools = () => {
  const { t_i18n } = useFormatter();

  const {
    graphState: {
      mode3D,
      modeTree,
      withForces,
    },
  } = useGraphContext();

  const {
    toggleForces,
    toggleHorizontalTree,
    toggleMode3D,
    toggleVerticalTree,
    zoomToFit,
    unfixNodes,
  } = useGraphInteractions();

  return (
    <>
      <GraphToolbarItem
        Icon={<Video3d />}
        color={mode3D ? 'secondary' : 'primary'}
        onClick={toggleMode3D}
        title={mode3D ? t_i18n('Disable 3D mode') : t_i18n('Enable 3D mode')}
      />

      <GraphToolbarItem
        Icon={<FamilyTree />}
        disabled={!withForces}
        color={modeTree === 'td' ? 'secondary' : 'primary'}
        onClick={toggleVerticalTree}
        title={modeTree ? t_i18n('Disable vertical tree mode') : t_i18n('Enable vertical tree mode')}
      />

      <GraphToolbarItem
        Icon={<FamilyTree style={{ transform: 'rotate(-90deg)' }} />}
        disabled={!withForces}
        color={modeTree === 'lr' ? 'secondary' : 'primary'}
        onClick={toggleHorizontalTree}
        title={modeTree ? t_i18n('Disable horizontal tree mode') : t_i18n('Enable horizontal tree mode')}
      />

      <GraphToolbarItem
        Icon={<ScatterPlotOutlined />}
        color={!withForces ? 'primary' : 'secondary'}
        onClick={toggleForces}
        title={modeTree ? t_i18n('Enable forces') : t_i18n('Disable forces')}
      />

      <GraphToolbarItem
        Icon={<AspectRatioOutlined />}
        color="primary"
        onClick={zoomToFit}
        title={t_i18n('Fit graph to canvas')}
      />

      <GraphToolbarItem
        Icon={<AutoFix />}
        disabled={!withForces}
        color="primary"
        onClick={unfixNodes}
        title={t_i18n('Unfix the nodes and re-apply forces')}
      />
    </>
  );
};

export default GraphToolbarDisplayTools;
