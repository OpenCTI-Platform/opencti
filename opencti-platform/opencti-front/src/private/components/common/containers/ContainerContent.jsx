import React, { useEffect, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import 'ckeditor5-custom-build/build/translations/fr';
import 'ckeditor5-custom-build/build/translations/zh-cn';
import 'react-pdf/dist/esm/Page/TextLayer.css';
import 'react-pdf/dist/esm/Page/AnnotationLayer.css';
import { makeStyles } from '@mui/styles';
import Grid from '@mui/material/Grid';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { EditOutlined, LayersClearOutlined } from '@mui/icons-material';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import { useFormatter } from '../../../../components/i18n';
import {
  useIsEnforceReference,
  useSchemaEditionValidation,
} from '../../../../utils/hooks/useEntitySettings';
import { SubscriptionFocus } from '../../../../components/Subscription';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import MarkdownField from '../../../../components/MarkdownField';
import CommitMessage from '../form/CommitMessage';
import RichTextField from '../../../../components/RichTextField';
import useFormEditor from '../../../../utils/hooks/useFormEditor';
import ContainerStixCoreObjectsMapping from './ContainerStixCoreObjectsMapping';
import { decodeMappingData, encodeMappingData } from '../../../../utils/Graph';
import Transition from '../../../../components/Transition';

const OPEN$ = new Subject().pipe(debounce(() => timer(500)));

export const contentMutationFieldPatch = graphql`
  mutation ContainerContentFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        ...ContainerContent_container
      }
    }
  }
`;

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
  editorContainer: {
    height: '100%',
    minHeight: '100%',
    margin: 0,
    padding: 0,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  clearButton: {
    float: 'right',
    marginTop: -15,
  },
  editButton: {
    float: 'left',
    marginTop: -15,
  },
}));

const ContainerContentComponent = ({ containerData }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const [editionMode, setEditionMode] = useState(false);
  const [openClearMapping, setOpenClearMapping] = useState(false);
  const [selectedText, setSelectedText] = useState(null);
  const [selectedTab, setSelectedTab] = useState('preview');
  const [clearing, setClearing] = useState(false);
  useEffect(() => {
    const subscription = OPEN$.subscribe({
      next: () => {
        setOpen(true);
      },
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);
  const enableReferences = useIsEnforceReference(containerData.entity_type);
  const { innerHeight } = window;
  const enrichedEditorHeight = innerHeight - 540;
  const listHeight = innerHeight - 340;
  const queries = {
    fieldPatch: contentMutationFieldPatch,
  };
  const basicShape = {
    content: Yup.string().nullable(),
    description: Yup.string().nullable(),
  };
  let validator = null;
  if (containerData.entity_type === 'Report') {
    validator = useSchemaEditionValidation('Report', basicShape);
  } else if (containerData.entity_type === 'Grouping') {
    validator = useSchemaEditionValidation('Grouping', basicShape);
  } else if (containerData.entity_type === 'Case-Incident') {
    validator = useSchemaEditionValidation('Case-Incident', basicShape);
  } else if (containerData.entity_type === 'Case-Rfi') {
    validator = useSchemaEditionValidation('Case-Rfi', basicShape);
  } else if (containerData.entity_type === 'Case-Rft') {
    validator = useSchemaEditionValidation('Case-Rft', basicShape);
  }
  const editor = useFormEditor(
    containerData,
    enableReferences,
    queries,
    validator,
  );
  const onSubmit = (values) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);
    editor.fieldPatch({
      variables: {
        id: containerData.id,
        input: otherValues,
        commitMessage:
          commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
    });
  };
  const handleSubmitField = (name, value) => {
    if (!enableReferences) {
      validator
        .validateAt(name, { [name]: value })
        .then(() => {
          editor.fieldPatch({
            variables: {
              id: containerData.id,
              input: { key: name, value: value || '' },
            },
          });
        })
        .catch(() => false);
    }
  };
  const handleTextSelection = (text) => {
    if (text && text.length > 2) {
      setSelectedText(text.trim());
      OPEN$.next({ action: 'OpenMapping' });
    }
  };
  const addMapping = (stixCoreObject) => {
    console.log(stixCoreObject);
    const { content_mapping } = containerData;
    const contentMappingData = decodeMappingData(content_mapping);
    const newMappingData = {
      ...contentMappingData,
      [selectedText.toLowerCase()]: stixCoreObject.standard_id,
    };
    editor.fieldPatch({
      variables: {
        id: containerData.id,
        input: {
          key: 'content_mapping',
          value: encodeMappingData(newMappingData),
        },
      },
      onCompleted: () => {
        setOpen(false);
        setSelectedText(null);
      },
    });
  };
  const clearMapping = () => {
    setClearing(true);
    editor.fieldPatch({
      variables: {
        id: containerData.id,
        input: {
          key: 'content_mapping',
          value: encodeMappingData({}),
        },
      },
      onCompleted: () => {
        setClearing(false);
        setOpenClearMapping(false);
      },
    });
  };
  const toggleEditionMode = () => {
    if (editionMode) {
      setSelectedTab('preview');
      setEditionMode(false);
    } else {
      setSelectedTab('write');
      setEditionMode(true);
    }
  };
  const handleChangeSelectedTab = (mode) => {
    if (editionMode) {
      setSelectedTab(mode);
    }
  };
  const matchCase = (text, pattern) => {
    let result = '';
    // eslint-disable-next-line no-plusplus
    for (let i = 0; i < text.length; i++) {
      const c = text.charAt(i);
      const p = pattern.charCodeAt(i);
      if (p >= 65 && p < 65 + 26) {
        result += c.toUpperCase();
      } else {
        result += c.toLowerCase();
      }
    }
    return result;
  };
  const { content_mapping } = containerData;
  const contentMappingData = decodeMappingData(content_mapping);
  const mappedStrings = Object.keys(contentMappingData);
  let { description, content } = containerData;
  const contentMapping = {};
  if (!editionMode) {
    for (const mappedString of mappedStrings) {
      const descriptionRegex = new RegExp(mappedString, 'ig');
      const descriptionCount = (
        (description || '').match(descriptionRegex) || []
      ).length;
      description = (description || '').replace(
        descriptionRegex,
        (match) => `==${matchCase(mappedString, match)}==`,
      );
      const contentRegex = new RegExp(mappedString, 'ig');
      const contentCount = ((content || '').match(contentRegex) || []).length;
      content = (content || '').replace(
        contentRegex,
        (match) => `<mark class="marker-yellow">${matchCase(mappedString, match)}</mark>`,
      );
      contentMapping[contentMappingData[mappedString]] = descriptionCount + contentCount;
    }
  }
  const initialValues = {
    description: description || '',
    content: content || '',
  };
  return (
    <div className={classes.container}>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ marginTop: -15 }}>
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ float: 'left' }}
          >
            {t('Content')}
          </Typography>
          <Tooltip title={t('Edition mode')}>
            <IconButton
              color={editionMode ? 'secondary' : 'primary'}
              aria-label="Edit"
              onClick={() => toggleEditionMode()}
              classes={{ root: classes.editButton }}
              size="large"
            >
              <EditOutlined fontSize="small" />
            </IconButton>
          </Tooltip>
          <>
            <Tooltip title={t('Clear mappings')}>
              <IconButton
                color="primary"
                aria-label="Apply"
                onClick={() => setOpenClearMapping(true)}
                classes={{ root: classes.clearButton }}
                size="large"
              >
                <LayersClearOutlined fontSize="small" />
              </IconButton>
            </Tooltip>
            <Dialog
              PaperProps={{ elevation: 1 }}
              open={openClearMapping}
              keepMounted={true}
              TransitionComponent={Transition}
              onClose={() => setOpenClearMapping(false)}
            >
              <DialogContent>
                <DialogContentText>
                  {t('Do you want to delete the mapping of this content?')}
                </DialogContentText>
              </DialogContent>
              <DialogActions>
                <Button
                  onClick={() => setOpenClearMapping(false)}
                  disabled={clearing}
                >
                  {t('Cancel')}
                </Button>
                <Button
                  color="secondary"
                  onClick={() => clearMapping()}
                  disabled={clearing}
                >
                  {t('Clear')}
                </Button>
              </DialogActions>
            </Dialog>
          </>
          <div className="clearfix" />
          <Paper
            classes={{ root: classes.paper }}
            variant="outlined"
            style={{ marginTop: -5 }}
          >
            <Formik
              enableReinitialize={true}
              initialValues={initialValues}
              validationSchema={validator}
              onSubmit={onSubmit}
            >
              {({
                submitForm,
                isSubmitting,
                setFieldValue,
                values,
                isValid,
                dirty,
              }) => (
                <Form styke={{ margin: 0 }}>
                  <Field
                    component={MarkdownField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    onSubmit={handleSubmitField}
                    onSelect={handleTextSelection}
                    helperText={
                      <SubscriptionFocus
                        context={containerData.editContext}
                        fieldName="description"
                      />
                    }
                    disabled={!editionMode}
                    controlledSelectedTab={selectedTab}
                    controlledSetSelectTab={handleChangeSelectedTab}
                  />
                  <Field
                    component={RichTextField}
                    name="content"
                    label={t('Content')}
                    fullWidth={true}
                    onSubmit={handleSubmitField}
                    onSelect={handleTextSelection}
                    style={{
                      ...fieldSpacingContainerStyle,
                      minHeight: enrichedEditorHeight,
                      height: enrichedEditorHeight,
                    }}
                    helperText={
                      <SubscriptionFocus
                        context={containerData.editContext}
                        fieldName="content"
                      />
                    }
                    disabled={!editionMode}
                  />
                  {enableReferences && (
                    <CommitMessage
                      submitForm={submitForm}
                      disabled={isSubmitting || !isValid || !dirty}
                      setFieldValue={setFieldValue}
                      open={false}
                      values={values.references}
                      id={containerData.id}
                    />
                  )}
                </Form>
              )}
            </Formik>
          </Paper>
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: -15 }}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Mapping')}
          </Typography>
          <Paper classes={{ root: classes.paper }} variant="outlined">
            <ContainerStixCoreObjectsMapping
              container={containerData}
              height={listHeight}
              selectedText={selectedText}
              openDrawer={open}
              handleClose={() => {
                setOpen(false);
                setSelectedText(null);
              }}
              addMapping={addMapping}
              contentMappingData={contentMappingData}
              contentMapping={contentMapping}
            />
          </Paper>
        </Grid>
      </Grid>
    </div>
  );
};

export const containerContentQuery = graphql`
  query ContainerContentQuery($id: String!) {
    container(id: $id) {
      ...ContainerContent_container
    }
  }
`;

const ContainerContent = createFragmentContainer(
  ContainerContentComponent,
  {
    containerData: graphql`
      fragment ContainerContent_container on Container {
        id
        standard_id
        entity_type
        confidence
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
          }
        }
        ... on Report {
          description
          content
          content_mapping
          editContext {
            name
            focusOn
          }
        }
        ... on Case {
          description
          content
          content_mapping
          editContext {
            name
            focusOn
          }
        }
        ... on Grouping {
          description
          content
          content_mapping
          editContext {
            name
            focusOn
          }
        }
      }
    `,
  },
  containerContentQuery,
);

export default ContainerContent;
