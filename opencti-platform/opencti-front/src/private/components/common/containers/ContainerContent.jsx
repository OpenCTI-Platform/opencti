import React, { useEffect, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import 'ckeditor5-custom-build/build/translations/fr';
import 'ckeditor5-custom-build/build/translations/zh-cn';
import 'react-pdf/dist/esm/Page/TextLayer.css';
import 'react-pdf/dist/esm/Page/AnnotationLayer.css';
import { makeStyles } from '@mui/styles';
import Grid from '@mui/material/Grid';
import * as Yup from 'yup';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { Subject, timer } from 'rxjs';
import { debounce } from 'rxjs/operators';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { LayersClearOutlined } from '@mui/icons-material';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import StixCoreObjectMappableContent from '../stix_core_objects/StixCoreObjectMappableContent';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference, useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
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

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 4,
  },
  clearButton: {
    float: 'right',
    marginTop: -15,
  },
}));

const ContainerContentComponent = ({ containerData }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [openClearMapping, setOpenClearMapping] = useState(false);
  const [selectedText, setSelectedText] = useState(null);
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
  const listHeight = innerHeight - 420;
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

  const handleTextSelection = (text) => {
    if (text && text.length > 2) {
      setSelectedText(text.trim());
      OPEN$.next({ action: 'OpenMapping' });
    }
  };

  const addMapping = (stixCoreObject) => {
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

  const { content_mapping } = containerData;
  const contentMappingData = decodeMappingData(content_mapping);
  const mappedStrings = Object.keys(contentMappingData);
  const { description, contentField } = containerData;
  const contentMapping = {};
  for (const mappedString of mappedStrings) {
    const escapedMappedString = mappedString.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const descriptionRegex = new RegExp(escapedMappedString, 'ig');
    const descriptionCount = (
      (description || '').match(descriptionRegex) || []
    ).length;
    const contentRegex = new RegExp(escapedMappedString, 'ig');
    const contentCount = ((contentField || '').match(contentRegex) || []).length;
    contentMapping[contentMappingData[escapedMappedString]] = descriptionCount + contentCount;
  }
  return (
    <div className={classes.container}>
      <Grid
        container
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ marginTop: -15 }}>
          <Typography
            variant="h4"
            gutterBottom
            style={{ float: 'left' }}
          >
            {t_i18n('Content')}
          </Typography>
          <Tooltip title={t_i18n('Clear mappings')}>
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
            keepMounted
            TransitionComponent={Transition}
            onClose={() => setOpenClearMapping(false)}
          >
            <DialogContent>
              <DialogContentText>
                {t_i18n('Do you want to delete the mapping of this content?')}
              </DialogContentText>
            </DialogContent>
            <DialogActions>
              <Button
                onClick={() => setOpenClearMapping(false)}
                disabled={clearing}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={() => clearMapping()}
                disabled={clearing}
              >
                {t_i18n('Clear')}
              </Button>
            </DialogActions>
          </Dialog>
          <div className="clearfix" />
          <StixCoreObjectMappableContent
            containerData={containerData}
            handleTextSelection={handleTextSelection}
            askAi={false}
            editionMode={false}
            mappedStrings={mappedStrings}
          />
        </Grid>
        <Grid item xs={6} style={{ marginTop: -15 }}>
          <Typography variant="h4" gutterBottom>
            {t_i18n('Mapping')}
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
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
        ... on Report {
          description
          contentField: content
          content_mapping
          editContext {
            name
            focusOn
          }
        }
        ... on Case {
          description
          contentField: content
          content_mapping
          editContext {
            name
            focusOn
          }
        }
        ... on Grouping {
          description
          contentField: content
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
