import React, { Dispatch, FunctionComponent, SyntheticEvent, useState } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import StixDomainObjectCreation from '@components/common/stix_domain_objects/StixDomainObjectCreation';
import Autocomplete from '@mui/material/Autocomplete';
import MUITextField from '@mui/material/TextField';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useMutation } from 'react-relay';
import { useHistory } from 'react-router-dom';
import { WorkspaceTurnToContainerDialogMutation } from '@components/workspaces/__generated__/WorkspaceTurnToContainerDialogMutation.graphql';
import { Option } from '@components/common/form/ReferenceField';
import Transition from '../../../components/Transition';
import { useFormatter } from '../../../components/i18n';
import ItemIcon from '../../../components/ItemIcon';
import { resolveLink } from '../../../utils/Entity';
import { handleError } from '../../../relay/environment';
import { Theme } from '../../../components/Theme';
import useSearchEntities, { EntityValue } from '../../../utils/filters/useSearchEntities';

const useStyles = makeStyles<Theme>((theme) => ({
  icon: {
    display: 'inline-block',
    paddingTop: 4,
    marginRight: theme.spacing(1),
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
  },
}));

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
  value?: Option;
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
  const classes = useStyles();
  const { t } = useFormatter();
  const [containerCreation, setContainerCreation] = useState(false);
  const [actionsInputs, setActionsInputs] = useState<ActionInputs | null>(null);
  const [targetContainerId, setTargetContainerId] = useState('');
  const [containers, setContainers] = useState<Record<string, EntityValue[]>>({});
  const [entities, searchEntities] = useSearchEntities({
    setInputValues: () => {},
    availableEntityTypes: [
      'Report',
      'Grouping',
      'Case-Incident',
      'Case-Rfi',
      'Case-Rft',
    ],
    allEntityTypes: false,
    availableRelationshipTypes: [],
    searchContext: { entityTypes: ['Container'] },
    searchScope: {},
  }) as [
    Record<string, EntityValue[]>,
    (
      filterKey: string,
      cacheEntities: Record<string, EntityValue[]>,
      setCacheEntities: Dispatch<Record<string, EntityValue[]>>,
      event: SyntheticEvent
    ) => Record<string, EntityValue[]>,
  ]; // change when useSearchEntities will be in TS;
  const containersFromElements = entities.containers ?? [
    {
      label: '',
      type: '',
      value: '',
    },
  ];

  const [commitInvestigationToContainerAdd] = useMutation<WorkspaceTurnToContainerDialogMutation>(
    investigationToContainerMutation,
  );
  const history = useHistory();
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
        history.push(
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
    searchEntities('containers', containers, setContainers, event);
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
      PaperProps={{ elevation: 1 }}
      fullWidth={true}
      maxWidth="sm"
      TransitionComponent={Transition}
      open={open}
      onClose={() => handleClose()}
    >
      <DialogTitle>{t('Turn to Report or Case')}</DialogTitle>
      <DialogContent>
        <StixDomainObjectCreation
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
            const element = {
              label: name,
              value: id,
              type: entity_type,
            };
            containersFromElements.push(element);
            handleChangeActionInputValues(null, [element]);
          }}
          confidence={undefined}
          defaultCreatedBy={undefined}
          defaultMarkingDefinitions={undefined}
          paginationKey={undefined}
          paginationOptions={undefined}
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
            <MUITextField
              {...params}
              variant="standard"
              label={t('Values')}
              fullWidth={true}
              onFocus={(event: React.SyntheticEvent<Element, Event>) => searchContainers(event)}
              style={{ marginTop: 3 }}
            />
          )}
          noOptionsText={t('No available options')}
          options={containersFromElements}
          onInputChange={(event, userInput) => searchContainers(event, userInput)}
          inputValue={actionsInputs?.inputValue || ''}
          onChange={(event, value) => handleChangeActionInputValues(event, value)}
          renderOption={(props, option) => (
            <li {...props}>
              <div className={classes.icon}>
                <ItemIcon type={option.type} />
              </div>
              <div className={classes.text}>{option.label}</div>
            </li>
          )}
          disableClearable
        />
        <IconButton
          onClick={() => setContainerCreation(true)}
          edge="end"
          style={{ position: 'absolute', top: 68, right: 48 }}
          size="large"
        >
          <Add />
        </IconButton>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => handleClose()}>
          {t('Cancel')}
        </Button>
        <Button
          color="secondary"
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
          {t('Add')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default WorkspaceTurnToContainerDialog;
