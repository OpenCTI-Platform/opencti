import React, { FunctionComponent, useState } from 'react';
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
import { graphql, useLazyLoadQuery, useMutation } from 'react-relay';
import { useHistory } from 'react-router-dom';
import { WorkspaceTurnToContainerDialogQuery } from '@components/workspaces/__generated__/WorkspaceTurnToContainerDialogQuery.graphql';
import { WorkspaceTurnToContainerDialogMutation } from '@components/workspaces/__generated__/WorkspaceTurnToContainerDialogMutation.graphql';
import Transition from '../../../components/Transition';
import { useFormatter } from '../../../components/i18n';
import ItemIcon from '../../../components/ItemIcon';
import { resolveLink } from '../../../utils/Entity';
import { handleError } from '../../../relay/environment';
import { Theme } from '../../../components/Theme';

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
  values?: Array<Container>;
}

interface Container {
  label?: string;
  type?: string;
  value?: string;
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

const WorkspaceTurnToContainerDialog: FunctionComponent<
WorkspaceTurnToContainerDialogProps
> = ({ workspace, open, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [containerCreation, setContainerCreation] = useState(false);
  const [containers, setContainers] = useState<Array<Container>>([]);
  const [actionsInputs, setActionsInputs] = useState<ActionInputs | null>(null);
  const [targetContainerId, setTargetContainerId] = useState('');
  const [newValue, setNewValue] = useState('');
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

  const searchContainersData = useLazyLoadQuery<WorkspaceTurnToContainerDialogQuery>(
    graphql`
        query WorkspaceTurnToContainerDialogQuery($search: String) {
          containers(
            search: $search
            filters: [{ key: entity_type, values: ["Container"] }]
          ) {
            edges {
              node {
                id
                entity_type
                representative {
                  main
                }
              }
            }
          }
        }
      `,
    { search: newValue ?? '' },
  );
  const searchContainers = (
    event: React.SyntheticEvent<Element, Event> | undefined,
    incomingValue?: string,
  ) => {
    if (!event) return;
    setNewValue(incomingValue || '');
    setActionsInputs({
      ...actionsInputs,
      inputValue: incomingValue ?? '',
    });

    const edges = searchContainersData?.containers?.edges;
    const elements = edges?.map((edge) => edge?.node);
    const containersFromElements = elements?.map((data) => ({
      label: data?.representative.main,
      type: data?.entity_type,
      value: data?.id,
    })) || [
      {
        label: '',
        type: '',
        value: '',
      },
    ];
    setContainers([...containersFromElements]);
  };

  const handleChangeActionInputValues = (
    event: React.SyntheticEvent<Element, Event> | null,
    value: Container[],
  ) => {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    setActionsInputs({
      ...(actionsInputs || {}),
      values: Array.isArray(value) ? value : [value],
    });
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
            setContainers([...(containers ?? []), element]);
            handleChangeActionInputValues(null, [
              ...(actionsInputs?.values ?? []),
              element,
            ]);
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
          getOptionLabel={(option) => option.label ?? ''}
          value={(actionsInputs?.values) || []}
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
          options={containers}
          onInputChange={(event, userInput) => searchContainers(event, userInput)}
          inputValue={actionsInputs?.inputValue || ''}
          onChange={(event, value) => handleChangeActionInputValues(event, value)
          }
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
