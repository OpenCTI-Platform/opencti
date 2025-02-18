import Drawer from '@mui/material/Drawer';
import React from 'react';
import { DeleteOutlined, LinkOutlined, VisibilityOutlined } from '@mui/icons-material';
import Divider from '@mui/material/Divider';
import { useTheme } from '@mui/material/styles';
import ContainerAddStixCoreObjectsInGraph from '@components/common/containers/ContainerAddStixCoreObjectsInGraph';
import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import { useFormatter } from '../../../components/i18n';
import GraphToolbarItem from './GraphToolbarItem';
import useGraphInteractions from '../utils/useGraphInteractions';
import SearchInput from '../../../components/SearchInput';
import type { Theme } from '../../../components/Theme';
import { GraphContainer } from '../graph.types';
import GraphToolbarEditObject from './GraphToolbarEditObject';
import GraphToolbarDisplayTools from './GraphToolbarDisplayTools';
import GraphToolbarSelectTools from './GraphToolbarSelectTools';
import GraphToolbarFilterTools from './GraphToolbarFilterTools';

interface GraphToolbarProps {
  stixCoreObjectRefetchQuery: GraphQLTaggedNode
  relationshipRefetchQuery: GraphQLTaggedNode
  container?: GraphContainer
  enableReferences?: boolean
}

const GraphToolbar = ({
  stixCoreObjectRefetchQuery,
  relationshipRefetchQuery,
  container,
  enableReferences,
}: GraphToolbarProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const navOpen = localStorage.getItem('navOpen') === 'true';

  const {
    selectBySearch,
    addNode,
    removeNode,
  } = useGraphInteractions();

  return (
    <Drawer
      anchor="bottom"
      variant="permanent"
      PaperProps={{
        elevation: 1,
        style: {
          zIndex: 1,
          paddingLeft: navOpen ? 180 : 60,
          height: 54,
        },
      }}
    >
      <div style={{
        height: 54,
        display: 'flex',
        alignItems: 'center',
        gap: theme.spacing(0.5),
        padding: `0 ${theme.spacing(0.5)}`,
      }}
      >
        <GraphToolbarDisplayTools />
        <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />

        <GraphToolbarSelectTools />
        <Divider sx={{ margin: 1, height: '80%' }} orientation="vertical" />

        <GraphToolbarFilterTools />
        <Divider sx={{ margin: 1, marginRight: 3, height: '80%' }} orientation="vertical" />

        <div style={{ flex: 1 }}>
          <SearchInput variant="thin" onSubmit={selectBySearch} />
        </div>

        {container && (
          <>
            <ContainerAddStixCoreObjectsInGraph
              knowledgeGraph={true} // TODO change for correlation?
              containerId={container.id}
              containerStixCoreObjects={container.objects}
              defaultCreatedBy={container.createdBy ?? null}
              defaultMarkingDefinitions={container.objectMarking ?? []}
              targetStixCoreObjectTypes={['Stix-Domain-Object', 'Stix-Cyber-Observable']}
              onAdd={addNode}
              onDelete={removeNode}
              confidence={container.confidence}
              enableReferences={enableReferences}
            />
            <GraphToolbarEditObject
              stixCoreObjectRefetchQuery={stixCoreObjectRefetchQuery}
              relationshipRefetchQuery={relationshipRefetchQuery}
            />
            <GraphToolbarItem
              Icon={<LinkOutlined />}
              disabled={false}
              color="primary"
              onClick={() => console.log('handleOpenCreateRelationship')}
              title={t_i18n('Create a relationship')}
            />
            <div>...</div>
            <GraphToolbarItem
              Icon={<VisibilityOutlined />}
              disabled={false}
              color="primary"
              onClick={() => console.log('handleOpenCreateSighting')}
              title={t_i18n('Create a sighting')}
            />
            <GraphToolbarItem
              Icon={<DeleteOutlined />}
              disabled={false}
              color="primary"
              onClick={() => console.log('handleOpenRemove')}
              title={t_i18n('Remove selected items')}
            />
          </>
        )}
      </div>
    </Drawer>
  );
};

export default GraphToolbar;
