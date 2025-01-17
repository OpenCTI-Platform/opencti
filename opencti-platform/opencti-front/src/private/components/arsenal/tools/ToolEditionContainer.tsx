import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ToolEditionOverview_tool$key } from '@components/arsenal/tools/__generated__/ToolEditionOverview_tool.graphql';
import Drawer, { DrawerControlledDialType, DrawerVariant } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ToolEditionOverview from './ToolEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useHelper from '../../../../utils/hooks/useHelper';
import { ToolEditionContainerQuery } from './__generated__/ToolEditionContainerQuery.graphql';

interface ToolEditionContainerProps {
  queryRef: PreloadedQuery<ToolEditionContainerQuery>
  handleClose: () => void
  open?: boolean
  controlledDial?: DrawerControlledDialType;
}

export const toolEditionQuery = graphql`
  query ToolEditionContainerQuery($id: String!) {
    tool(id: $id) {
      ...ToolEditionOverview_tool
      editContext {
        name
        focusOn
      }
    }
  }
`;

const ToolEditionContainer: FunctionComponent<ToolEditionContainerProps> = ({
  queryRef,
  handleClose,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { tool } = usePreloadedQuery(toolEditionQuery, queryRef);

  return (
    <Drawer
      title={t_i18n('Update a tool')}
      open={open}
      onClose={handleClose}
      variant={!isFABReplaced && open == null ? DrawerVariant.update : undefined}
      context={tool?.editContext}
      controlledDial={isFABReplaced ? controlledDial : undefined}
    >
      <ToolEditionOverview
        toolRef={tool as ToolEditionOverview_tool$key}
        enableReferences={useIsEnforceReference('Tool')}
        context={tool?.editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

export default ToolEditionContainer;
