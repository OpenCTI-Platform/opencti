import React, { Dispatch, FunctionComponent, SyntheticEvent, useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import StixDomainObjectCreation from '@components/common/stix_domain_objects/StixDomainObjectCreation';
import Autocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';
import IconButton from '@common/button/IconButton';
import { AddOutlined } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { WorkspaceTurnToContainerDialogMutation } from '@components/workspaces/__generated__/WorkspaceTurnToContainerDialogMutation.graphql';
import type { FilterOption } from '@components/common/lists/FilterAutocomplete';
import { useTheme } from '@mui/styles';
import Transition from '../../../components/Transition';
import { useFormatter } from '../../../components/i18n';
import ItemIcon from '../../../components/ItemIcon';
import { resolveLink } from '../../../utils/Entity';
import { handleError } from '../../../relay/environment';
import useSearchEntities, { EntityValue } from '../../../utils/filters/useSearchEntities';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../components/Theme';

interface WorkspaceTurnToContainerDialogProps {
  workspace: { id: string | null };
  open: boolean;
  handleClose: () => void;
}

interface ActionInputs {
  type?: string;
  fieldType?: string;
  field?: string;
  inputValue?: string;
  value?: FilterOption;
}

interface StixContainer {
  name?: string;
  entity_type?: string;
  id?: string;
}

const investigationToContainerMutation = graphql`
  mutation WorkspaceTurnToContainerDialogMutation(
    $containerId: ID!
    $workspaceId: ID!
  ) {
    containerEdit(id: $containerId) {
      knowledgeAddFromInvestigation(workspaceId: $workspaceId) {
        id
        entity_type
      }
    }
  }
`;

const WorkspaceTurnToContainerDialog: FunctionComponent<WorkspaceTurnToContainerDialogProps> = ({ workspace, open, handleClose }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [containerCreation, setContainerCreation] = useState(false);
  const [actionsInputs, setActionsInputs] = useState<ActionInputs | null>(null);
  const [targetContainerId, setTargetContainerId] = useState('');
  const [containers, setContainers] = useState<Record<string, EntityValue[]>>({});
  const [entities, searchEntities] = useSearchEntities({
    setInputValues: () => {},
    availableRelationshipTypes: [],
    searchContext: { entityTypes: ['Container'] },
    searchScope: {
      id: [
        'Report',
        'Grouping',
        'Case-Incident',
        'Case-Rfi',
        'Case-Rft',
      ],
    },
  }) as [
    Record<string, EntityValue[]>,
    (
      filterKey: string,
      cacheEntities: Record<string, EntityValue[]>,
      setCacheEntities: Dispatch<Record<string, EntityValue[]>>,
      event: SyntheticEvent,
    ) => Record<string, EntityValue[]>,
  ]; // change when useSearchEntities will be in TS;
  const containersFromElements = entities.id ?? [];

  const [commitInvestigationToContainerAdd] = useApiMutation<WorkspaceTurnToContainerDialogMutation>(
    investigationToContainerMutation,
  );
  const navigate = useNavigate();
  const handleCloseUpdate = () => {
    setActionsInputs(null);
  };
  const handleLaunchUpdate = () => {
    handleCloseUpdate();
    commitInvestigationToContainerAdd({
      variables: {
        containerId: targetContainerId,
        workspaceId: workspace.id || '',
      },
      onCompleted: (data) => {
        const id = data.containerEdit?.knowledgeAddFromInvestigation?.id;
        const entityType = data.containerEdit?.knowledgeAddFromInvestigation?.entity_type || '';
        navigate(
          `${resolveLink(entityType.toString())}/${id}/knowledge/graph`,
        );
      },
      onError: (error) => {
        handleError(error);
      },
    });
  };

  const searchContainers = (
    event: React.SyntheticEvent<Element, Event> | undefined,
    incomingValue?: string,
  ) => {
    if (!event) return;
    searchEntities('id', containers, setContainers, event);
    setActionsInputs({
      ...actionsInputs,
      inputValue: incomingValue ?? '',
    });
  };

  const handleChangeActionInputValues = (
    event: React.SyntheticEvent<Element, Event> | null,
    value: EntityValue[],
  ) => {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    setActionsInputs({
      ...(actionsInputs || {}),
      value: Array.isArray(value) ? value.at(-1) : value,
    } as ActionInputs);
    setTargetContainerId(value[0]?.value ?? '');
  };

  return (
    <Dialog
      slotProps={{ paper: { elevation: 1 } }}
      fullWidth={true}
      maxWidth="sm"
      slots={{ transition: Transition }}
      open={open}
      onClose={() => handleClose()}
    >
      <DialogTitle>{t_i18n('Add to container')}</DialogTitle>
      <DialogContent>
        <StixDomainObjectCreation
          isFromBulkRelation={undefined}
          inputValue={actionsInputs?.inputValue || ''}
          open={containerCreation}
          display={true}
          speeddial={true}
          stixDomainObjectTypes={[
            'Report',
            'Grouping',
            'Case-Incident',
            'Case-Rfi',
            'Case-Rft',
          ]}
          handleClose={() => setContainerCreation(false)}
          creationCallback={({ name, id, entity_type }: StixContainer) => {
            if (name && id && entity_type) {
              const element = {
                label: name,
                value: id,
                type: entity_type,
              };
              containersFromElements.push(element);
              handleChangeActionInputValues(null, [element]);
            }
          }}
          confidence={undefined}
          defaultCreatedBy={undefined}
          defaultMarkingDefinitions={undefined}
          onCompleted={undefined}
          paginationKey={undefined}
          paginationOptions={undefined}
          // controlledDial={undefined}
        />
        <Autocomplete
          size="small"
          fullWidth={true}
          selectOnFocus={true}
          autoHighlight={true}
          getOptionLabel={(option) => option?.label ?? ''}
          value={actionsInputs?.value ? [actionsInputs.value] : []}
          multiple={true}
          renderInput={(params) => (
            <TextField
              {...params}
              variant="standard"
              label={t_i18n('Container')}
              fullWidth={true}
              onFocus={(event: React.SyntheticEvent<Element, Event>) => searchContainers(event)}
              style={{ marginTop: 3 }}
            />
          )}
          noOptionsText={t_i18n('No available options')}
          options={containersFromElements}
          onInputChange={(event, userInput) => searchContainers(event, userInput)}
          inputValue={actionsInputs?.inputValue || ''}
          onChange={(event, value) => handleChangeActionInputValues(event, value as EntityValue[])}
          renderOption={(props, option) => (
            <li {...props}>
              <div style={{
                display: 'inline-block',
                paddingTop: 4,
                marginRight: theme.spacing(1),
              }}
              >
                <ItemIcon type={option.type} />
              </div>
              <div style={{
                display: 'inline-block',
                flexGrow: 1,
              }}
              >
                {option.label}
              </div>
            </li>
          )}
          disableClearable
        />
        <IconButton
          onClick={() => setContainerCreation(true)}
          // edge="end"
          style={{ position: 'absolute', top: 68, right: 48 }}
        >
          <AddOutlined />
        </IconButton>
      </DialogContent>
      <DialogActions>
        <Button variant="secondary" onClick={() => handleClose()}>
          {t_i18n('Cancel')}
        </Button>
        <Button
          onClick={() => {
            handleClose();
            setActionsInputs({
              ...actionsInputs,
              type: 'ADD',
              fieldType: 'ATTRIBUTE',
              field: 'container-object',
            });
            handleLaunchUpdate();
          }}
        >
          {t_i18n('Add')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default WorkspaceTurnToContainerDialog;
