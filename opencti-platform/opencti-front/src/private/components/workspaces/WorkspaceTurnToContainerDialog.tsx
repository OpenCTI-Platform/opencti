import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import type { FilterOption } from '@components/common/lists/FilterAutocomplete';
import StixDomainObjectCreation from '@components/common/stix_domain_objects/StixDomainObjectCreation';
import { WorkspaceTurnToContainerDialogMutation } from '@components/workspaces/__generated__/WorkspaceTurnToContainerDialogMutation.graphql';
import { AddOutlined } from '@mui/icons-material';
import {
  Combobox,
  ComboboxChangeMeta,
  ComboboxChips,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
} from '@filigran/design-system';
import DialogActions from '@mui/material/DialogActions';
import { useTheme } from '@mui/styles';
import React, { Dispatch, FunctionComponent, SyntheticEvent, useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../components/i18n';
import ItemIcon from '../../../components/ItemIcon';
import type { Theme } from '../../../components/Theme';
import { handleError } from '../../../relay/environment';
import { resolveLink } from '../../../utils/Entity';
import useSearchEntities, { EntityValue } from '../../../utils/filters/useSearchEntities';
import useApiMutation from '../../../utils/hooks/useApiMutation';

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

  // The `if (!event) return` guard this function used to open with is gone: the
  // engine states the CAUSE of every change, so the call site gates on
  // `meta.cause === 'type'` and this only ever runs for a keystroke. The event
  // is still threaded through because the shared `searchEntities` helper reads
  // `event.target.value` off it.
  const searchContainers = (
    event: React.SyntheticEvent<Element, Event>,
    incomingValue?: string,
  ) => {
    searchEntities('id', containers, setContainers, event);
    setActionsInputs({
      ...actionsInputs,
      inputValue: incomingValue ?? '',
    });
  };

  const handleChangeActionInputValues = (
    event: React.SyntheticEvent<Element, Event> | null | undefined,
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
      open={open}
      onClose={() => handleClose()}
      title={t_i18n('Add to container')}
    >
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
      <Combobox<EntityValue>
        multiple
        // MUI parity: none of these mounts passed disableCloseOnSelect, so the panel
        // closed after each pick. The library keeps it open in multiple mode, which
        // overlays the form's own action button in a dialog this narrow.
        closeOnSelect
        options={containersFromElements}
        // `actionsInputs.value` is declared as the loose FilterOption while the
        // options are the narrower FilterOptionValue. The value only ever comes
        // from the options, and the MUI original cast in the same direction on
        // its own onChange (`value as EntityValue[]`).
        value={actionsInputs?.value ? [actionsInputs.value as EntityValue] : []}
        onValueChange={(next, meta) => handleChangeActionInputValues(
          meta.event,
          (next ?? []) as EntityValue[],
        )}
        inputValue={actionsInputs?.inputValue || ''}
        // Keystroke only. The server query used to be wired to every reason MUI
        // reported, which is why searchContainers opened with `if (!event)
        // return` — one of the 28 sites the completion wave counted.
        onInputChange={(userInput: string, meta: ComboboxChangeMeta) => {
          if (meta.cause === 'type' && meta.event) searchContainers(meta.event, userInput);
        }}
        getOptionLabel={(option) => option?.label ?? ''}
        isOptionEqualToValue={(a, b) => a.value === b.value}
        clearable={false}
        renderOption={(option) => (
          <>
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
          </>
        )}
      >
        <ComboboxLabel>{t_i18n('Container')}</ComboboxLabel>
        <ComboboxField>
          <ComboboxChips />
          <ComboboxInput />
          <ComboboxControls>
            <ComboboxTrigger />
          </ComboboxControls>
        </ComboboxField>
        <ComboboxContent
          emptyMessage={t_i18n('No available options')}
          listAriaLabel={t_i18n('Container')}
        />
      </Combobox>
      <IconButton
        aria-label={t_i18n('Add')}
        onClick={() => setContainerCreation(true)}
        style={{ position: 'absolute', top: 68, right: 48 }}
      >
        <AddOutlined />
      </IconButton>
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
