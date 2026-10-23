import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined, CheckCircleOutlined, DoNotDisturbOnOutlined } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton } from '@mui/material';
import { Link } from 'react-router';
import { styled } from '@mui/material/styles';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import { useFormatter } from '../../../../components/i18n';
import { SubTypesLine_node$key } from './__generated__/SubTypesLine_node.graphql';
import { Checkbox } from '@filigran/design-system';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

const subTypesLinesFragment = graphql`
  fragment SubTypesLine_node on SubType {
    id
    label
    workflowEnabled
    settings {
      id
      enforce_reference
      platform_entity_files_ref
      platform_hidden_type
      target_type
      availableSettings
      workflow_published_version_id
    }
    statuses {
      id
      order
      template {
        name
        color
      }
    }
  }
`;

interface SubTypeLineProps {
  node: SubTypesLine_node$key;
  dataColumns: DataColumns;
  selectedElements: Record<string, { id: string }>;
  deSelectedElements: Record<string, { id: string }>;
  selectAll: boolean;
  onToggleEntity: (entity: { id: string }, event: React.SyntheticEvent) => void;
  onToggleShiftEntity: (
    index: number,
    entity: { id: string },
    event: React.SyntheticEvent,
  ) => void;
  index: number;
}

const SubTypeLine: FunctionComponent<SubTypeLineProps> = ({
  node,
  dataColumns,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
  onToggleShiftEntity,
  index,
}) => {
  const { t_i18n } = useFormatter();
  const nodeSubType = useFragment(subTypesLinesFragment, node);

  const renderOptionIcon = (option: string) => {
    if (!nodeSubType.settings?.availableSettings?.includes(option)) {
      return <DoNotDisturbOnOutlined fontSize="small" color="disabled" />;
    }
    if ((nodeSubType.settings as never)?.[option] === true) {
      return <CheckCircleOutlined fontSize="small" color="success" />;
    }
    return <DoNotDisturbOnOutlined fontSize="small" color="primary" />;
  };
  const renderWorkflowStatus = () => {
    if (!nodeSubType.settings?.availableSettings?.includes('workflow_configuration')) {
      return <DoNotDisturbOnOutlined fontSize="small" color="disabled" />;
    }
    if (nodeSubType.label === 'DraftWorkspace') {
      return nodeSubType.settings?.workflow_published_version_id
        ? <CheckCircleOutlined fontSize="small" color="success" />
        : <DoNotDisturbOnOutlined fontSize="small" color="primary" />;
    }
    if (nodeSubType.workflowEnabled) {
      return <CheckCircleOutlined fontSize="small" color="success" />;
    }
    return <DoNotDisturbOnOutlined fontSize="small" color="primary" />;
  };
  return (
    <ListItemButton
      key={nodeSubType.id}
      divider={true}
      sx={{ paddingLeft: '10px', height: 50 }}
      component={Link}
      to={`/dashboard/settings/customization/entity_types/${nodeSubType.id}`}
    >
      <ListItemIcon
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, { id: nodeSubType.id }, event)
          : onToggleEntity({ id: nodeSubType.id }, event))
        }
        sx={{ color: (theme) => theme.palette.primary.main }}
        style={{ minWidth: 40 }}
      >
        <Checkbox
          checked={
            (selectAll && !(nodeSubType.id in (deSelectedElements || {})))
            || nodeSubType.id in (selectedElements || {})
          }
        />
      </ListItemIcon>
      <ListItemIcon sx={{ color: (theme) => theme.palette.primary.main }}>
        <ItemIcon type={nodeSubType.id} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.entity_type.width }}
            >
              {t_i18n(`entity_${nodeSubType.label}`)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.workflow_status.width }}
            >
              {renderWorkflowStatus()}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.enforce_reference.width }}
            >
              {renderOptionIcon('enforce_reference')}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.automatic_references.width }}
            >
              {renderOptionIcon('platform_entity_files_ref')}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.hidden.width }}
            >
              {renderOptionIcon('platform_hidden_type')}
            </BodyItem>
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export default SubTypeLine;

export const SubTypeLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  return (
    <ListItem divider={true} sx={{ paddingLeft: '10px', height: 50 }}>
      <ListItemIcon style={{ minWidth: 40 }}>
        <Checkbox
          disabled={true}
        />
      </ListItemIcon>
      <ListItemIcon>
        <Skeleton
          animation="wave"
          variant="circular"
          width={30}
          height={30}
        />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.values(dataColumns).map((value) => (
              <BodyItem
                key={value.label}
                style={{ width: value.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height={20}
                />
              </BodyItem>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};
