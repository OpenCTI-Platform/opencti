import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import Tag from '@common/tag/Tag';
import { AddOutlined, CloseOutlined, Delete } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItemText from '@mui/material/ListItemText';
import { SelectChangeEvent } from '@mui/material/Select';
import Slide from '@mui/material/Slide';
import TextField from '@mui/material/TextField';
import Tooltip from '@mui/material/Tooltip';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { DotsHorizontalCircleOutline } from 'mdi-material-ui';
import { useState } from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import { MESSAGING$ } from 'src/relay/environment';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE } from 'src/utils/hooks/useGranted';
import Security from 'src/utils/Security';

const workspaceMutation = graphql`
  mutation WorkspaceHeaderTagManagerFieldMutation($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) {
      tags
    }
  }
`;

type WorkspaceHeaderTagManagerProps = {
  tags: readonly string[];
  workspaceId: string;
  canEdit: boolean;
};

export type WorkspaceHeaderTagCreatorFormValues = {
  newTag: string;
};
const WorkspaceHeaderTagManager = ({ tags, workspaceId, canEdit }: WorkspaceHeaderTagManagerProps) => {
  const { t_i18n } = useFormatter();

  const [newTag, setNewTag] = useState<string>('');
  const [isTagInputOpen, setIsTagInputOpen] = useState<boolean>(false);
  const [isTagDialogOpen, setIsTagDialogOpen] = useState<boolean>(false);

  const [commit] = useApiMutation(workspaceMutation);

  const toggleTagInput = () => setIsTagInputOpen(!isTagInputOpen);
  const toggleTagDialog = () => setIsTagDialogOpen(!isTagDialogOpen);

  const handleChangeNewTag = (event: SelectChangeEvent) => setNewTag(event.target.value);

  const handleManageTags = (tagList: string[], message: string) => {
    commit({
      variables: {
        id: workspaceId,
        input: {
          key: 'tags',
          value: tagList,
        },
      },
      onCompleted: () => MESSAGING$.notifySuccess(message),
    });
  };
  const deleteTag = (tagToDelete: string) => () => {
    const filteredTags = tags.filter((tag) => tag !== tagToDelete);
    handleManageTags(filteredTags, t_i18n('The tag has been removed'));
  };

  const onSubmitCreateTag: FormikConfig<WorkspaceHeaderTagCreatorFormValues>['onSubmit'] = (data, { resetForm }) => {
    if (!tags.includes(newTag) && newTag !== '') {
      handleManageTags([...tags, newTag], t_i18n('The tag has been added'));
    }
    if (isTagInputOpen) toggleTagInput();
    setNewTag('');
    resetForm();
  };

  return (
    <>
      <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]} hasAccess={canEdit}>
        <>
          {tags.length > 1 ? (
            <IconButton
              color="primary"
              aria-label="More"
              onClick={toggleTagDialog}
            >
              <DotsHorizontalCircleOutline fontSize="small" />
            </IconButton>
          ) : (
            <Tooltip title={isTagInputOpen ? t_i18n('Cancel') : t_i18n('Add tag')}>
              <IconButton
                color="primary"
                aria-label="Add tag"
                onClick={toggleTagInput}
              >
                {isTagInputOpen ? (
                  <CloseOutlined fontSize="small" />
                ) : (
                  <AddOutlined fontSize="small" />
                )}
              </IconButton>
            </Tooltip>
          )}

          <Slide
            direction="right"
            in={isTagInputOpen}
            mountOnEnter
            unmountOnExit
          >
            <div>
              <Formik
                initialValues={{ newTag: '' }}
                onSubmit={onSubmitCreateTag}
              >
                <Form>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="newTag"
                    aria-label="tag field"
                    autoFocus
                    placeholder={t_i18n('New tag')}
                    onChange={handleChangeNewTag}
                    value={newTag}
                  />
                </Form>
              </Formik>
            </div>
          </Slide>

          <Dialog
            open={isTagDialogOpen}
            onClose={toggleTagDialog}
            title={t_i18n('Entity tags')}
          >
            <Formik
              initialValues={{ newTag: '' }}
              onSubmit={onSubmitCreateTag}
            >
              <Form style={{ float: 'right' }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="newTag"
                  autoFocus
                  placeholder={t_i18n('New tag')}
                  onChange={handleChangeNewTag}
                  value={newTag}
                />
              </Form>
            </Formik>

            <List>
              {tags.map(
                (label) => label.length > 0 && (
                  <ListItem
                    key={label}
                    disableGutters
                    dense
                  >
                    <ListItemText primary={label} />
                    <ListItemSecondaryAction>
                      <IconButton
                        aria-label="delete"
                        onClick={deleteTag(label)}
                      >
                        <Delete />
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                ),
              )}
            </List>

            <DialogActions>
              <Button onClick={toggleTagDialog}>
                {t_i18n('Close')}
              </Button>
            </DialogActions>
          </Dialog>
        </>
      </Security>
      <div style={{ display: 'flex', gap: 7 }}>
        {tags.slice(0, 2).map(
          (tag) => tag.length > 0 && (
            <Tag
              key={tag}
              label={tag}
              onDelete={deleteTag(tag)}
            />
          ),
        )}
      </div>
    </>
  );
};

export default WorkspaceHeaderTagManager;
