import React, { FunctionComponent, useState } from 'react';
import { includes } from 'ramda';
import { createPaginationContainer, graphql, RelayPaginationProp } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import { ExpandLessOutlined, ExpandMoreOutlined, OpenInBrowserOutlined } from '@mui/icons-material';
import Slide, { SlideProps } from '@mui/material/Slide';
import { Field, Form, Formik } from 'formik';
import DialogTitle from '@mui/material/DialogTitle';
import MenuItem from '@mui/material/MenuItem';
import * as Yup from 'yup';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { Link } from 'react-router-dom';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { FileLine_file$data } from '@components/common/files/__generated__/FileLine_file.graphql';
import { truncate } from '../../../../utils/String';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import AddExternalReferences from './AddExternalReferences';
import { externalReferenceMutationRelationDelete } from './AddExternalReferencesLines';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import ExternalReferenceEnrichment from './ExternalReferenceEnrichment';
import FileLine from '../../common/files/FileLine';
import FileUploader from '../../common/files/FileUploader';
import ExternalReferencePopover from './ExternalReferencePopover';
import SelectField from '../../../../components/SelectField';
import { scopesConn, stixCoreObjectFilesAndHistoryAskJobImportMutation } from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { deleteNodeFromId } from '../../../../utils/store';
import { StixCoreObjectExternalReferencesLines_data$data } from './__generated__/StixCoreObjectExternalReferencesLines_data.graphql';
import { isNotEmptyField } from '../../../../utils/utils';
import ItemIcon from '../../../../components/ItemIcon';

const useStyles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: 0,
    borderRadius: 4,
    position: 'relative',
  },
  buttonExpand: {
    position: 'absolute',
    left: 0,
    bottom: 0,
    width: '100%',
    height: 25,
    color: theme.palette.primary.main,
    backgroundColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
    borderTopLeftRadius: 0,
    borderTopRightRadius: 0,
    '&:hover': {
      backgroundColor:
        theme.palette.mode === 'dark'
          ? 'rgba(255, 255, 255, .2)'
          : 'rgba(0, 0, 0, .2)',
    },
  },
}));

const Transition = React.forwardRef((props: SlideProps, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const importValidation = (t: (value: string) => string) => Yup.object().shape({
  connector_id: Yup.string().required(t('This field is required')),
});

interface StixCoreObjectExternalReferencesLinesContainerProps {
  stixCoreObjectId: string;
  data: StixCoreObjectExternalReferencesLines_data$data;
  relay: RelayPaginationProp;
}

const StixCoreObjectExternalReferencesLinesContainer: FunctionComponent<
StixCoreObjectExternalReferencesLinesContainerProps
> = ({ stixCoreObjectId, data, relay }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [displayDialog, setDisplayDialog] = useState(false);
  const [displayExternalLink, setDisplayExternalLink] = useState(false);
  const [externalLink, setExternalLink] = useState<string | URL | undefined>(
    undefined,
  );
  const [externalReferenceToRemove, setExternalReferenceToRemove] = useState<externalReferenceEdge_type | null>(null);
  const [removing, setRemoving] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [fileToImport, setFileToImport] = useState<FileLine_file$data | null>(null);
  const externalReferencesEdges = data.stixCoreObject
    ? data.stixCoreObject.externalReferences?.edges
    : [];
  const firstExternalReferenceEdge = externalReferencesEdges?.map((o) => o)[0];
  type externalReferenceEdge_type = typeof firstExternalReferenceEdge;
  const expandable = externalReferencesEdges
    ? externalReferencesEdges.length > 7
    : false;
  const importConnsPerFormat = data.connectorsForImport
    ? scopesConn(data.connectorsForImport)
    : {};
  const handleToggleExpand = () => {
    setExpanded(!expanded);
  };
  const handleOpenDialog = (
    externalReferenceEdge: externalReferenceEdge_type,
  ) => {
    setDisplayDialog(true);
    setExternalReferenceToRemove(externalReferenceEdge);
  };
  const handleCloseDialog = () => {
    setDisplayDialog(false);
    setExternalReferenceToRemove(null);
  };
  const handleOpenExternalLink = (url: string) => {
    setDisplayExternalLink(true);
    setExternalLink(url);
  };
  const handleCloseExternalLink = () => {
    setDisplayExternalLink(false);
    setExternalLink(undefined);
  };
  const handleBrowseExternalLink = () => {
    window.open(externalLink, '_blank');
    setDisplayExternalLink(false);
    setExternalLink(undefined);
  };
  const removeExternalReference = (
    externalReferenceEdge: externalReferenceEdge_type | null,
  ) => {
    commitMutation({
      mutation: externalReferenceMutationRelationDelete,
      variables: {
        id: externalReferenceEdge?.node.id,
        fromId: stixCoreObjectId,
        relationship_type: 'external-reference',
      },
      updater: (store: RecordSourceSelectorProxy) => {
        deleteNodeFromId(
          store,
          stixCoreObjectId,
          'Pagination_externalReferences',
          undefined,
          externalReferenceEdge?.node.id,
        );
      },
      onCompleted: () => {
        setRemoving(false);
        handleCloseDialog();
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };
  const handleRemoval = () => {
    setRemoving(true);
    removeExternalReference(externalReferenceToRemove);
  };
  const handleOpenImport = (
    file?: FileLine_file$data,
  ) => {
    if (file) {
      setFileToImport(file);
    }
  };
  const handleCloseImport = () => {
    setFileToImport(null);
  };
  const onSubmitImport: FormikConfig<{ connector_id: string }>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    commitMutation({
      mutation: stixCoreObjectFilesAndHistoryAskJobImportMutation,
      variables: {
        fileName: fileToImport?.id,
        connectorId: values.connector_id,
        bypassEntityId: stixCoreObjectId,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseImport();
        MESSAGING$.notifySuccess('Import successfully asked');
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('External references')}
      </Typography>
      <Security
        needs={[KNOWLEDGE_KNUPDATE]}
        placeholder={<div style={{ height: 29 }} />}
      >
        <AddExternalReferences
          stixCoreObjectOrStixCoreRelationshipId={stixCoreObjectId}
          stixCoreObjectOrStixCoreRelationshipReferences={
            data.stixCoreObject
              ? data.stixCoreObject.externalReferences?.edges
              : []
          }
        />
      </Security>
      <div className="clearfix" />
      <Paper classes={{ root: classes.paper }} variant="outlined">
        {(
          externalReferencesEdges ? externalReferencesEdges.length > 0 : false
        ) ? (
          <List style={{ marginBottom: 0 }}>
            {externalReferencesEdges
              ?.slice(0, expanded ? 200 : 7)
              .map((externalReferenceEdge) => {
                const externalReference = externalReferenceEdge.node;
                const isFileAttached = isNotEmptyField(
                  externalReference.fileId,
                );
                const externalReferenceId = externalReference.external_id
                  ? `(${externalReference.external_id})`
                  : '';
                let externalReferenceSecondary = '';
                if (externalReference.url && externalReference.url.length > 0) {
                  externalReferenceSecondary = externalReference.url;
                } else if (
                  externalReference.description
                  && externalReference.description.length > 0
                ) {
                  externalReferenceSecondary = externalReference.description;
                } else {
                  externalReferenceSecondary = t_i18n('No description');
                }
                if (externalReference.url && !isFileAttached) {
                  return (
                    <React.Fragment key={externalReference.id}>
                      <ListItem
                        component={Link}
                        to={`/dashboard/analyses/external_references/${externalReference.id}`}
                        dense={true}
                        divider={true}
                        button={true}
                      >
                        <ListItemIcon>
                          <ItemIcon type="External-Reference" />
                        </ListItemIcon>
                        <ListItemText
                          primary={truncate(
                            `${externalReference.source_name} ${externalReferenceId}`,
                            70,
                          )}
                          secondary={truncate(externalReferenceSecondary, 70)}
                        />
                        <ListItemSecondaryAction>
                          <Tooltip title={t_i18n('Browse the link')}>
                            <IconButton
                              onClick={() => handleOpenExternalLink(
                                externalReference.url ?? '',
                              )
                              }
                              size="large"
                              color="primary"
                            >
                              <OpenInBrowserOutlined />
                            </IconButton>
                          </Tooltip>
                          <Security needs={[KNOWLEDGE_KNUPLOAD]}>
                            <FileUploader
                              entityId={externalReference.id}
                              onUploadSuccess={() => relay.refetchConnection(200)
                              }
                              size={undefined}
                            />
                          </Security>
                          <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
                            <ExternalReferenceEnrichment
                              externalReferenceId={externalReference.id}
                            />
                          </Security>
                          <Security needs={[KNOWLEDGE_KNUPDATE]}>
                            <ExternalReferencePopover
                              id={externalReference.id}
                              handleRemove={() => handleOpenDialog(externalReferenceEdge)
                              }
                              objectId={stixCoreObjectId}
                            />
                          </Security>
                        </ListItemSecondaryAction>
                      </ListItem>
                      {externalReference.importFiles?.edges
                        && externalReference.importFiles?.edges.length > 0 && (
                          <List>
                            {externalReference.importFiles.edges.map(
                              (file) => file?.node && (
                              <FileLine
                                key={file.node.id}
                                dense={true}
                                file={file.node}
                                nested={true}
                                workNested={true}
                                onDelete={() => relay.refetchConnection(200)
                                    }
                                connectors={
                                      importConnsPerFormat[
                                        file.node.metaData?.mimetype ?? 0
                                      ]
                                    }
                                handleOpenImport={handleOpenImport}
                              />
                              ),
                            )}
                          </List>
                      )}
                    </React.Fragment>
                  );
                }
                return (
                  <React.Fragment key={externalReference.id}>
                    <ListItem
                      component={Link}
                      to={`/dashboard/analyses/external_references/${externalReference.id}`}
                      dense={true}
                      divider={true}
                      button={true}
                    >
                      <ListItemIcon>
                        <ItemIcon type="External-Reference" />
                      </ListItemIcon>
                      <ListItemText
                        primary={`${externalReference.source_name} ${externalReferenceId}`}
                        secondary={truncate(externalReference.description, 120)}
                      />
                      <ListItemSecondaryAction>
                        {!isFileAttached && (
                          <Security needs={[KNOWLEDGE_KNUPLOAD]}>
                            <FileUploader
                              entityId={externalReference.id}
                              onUploadSuccess={() => relay.refetchConnection(200)
                              }
                              size={undefined}
                            />
                          </Security>
                        )}
                        <Security needs={[KNOWLEDGE_KNUPDATE]}>
                          <ExternalReferencePopover
                            id={externalReference.id}
                            isExternalReferenceAttachment={isFileAttached}
                            handleRemove={() => handleOpenDialog(externalReferenceEdge)
                            }
                          />
                        </Security>
                      </ListItemSecondaryAction>
                    </ListItem>
                    {externalReference.importFiles?.edges
                      && externalReference.importFiles?.edges.length > 0 && (
                        <List>
                          {externalReference.importFiles?.edges?.map(
                            (file) => file?.node && (
                            <FileLine
                              key={file.node.id}
                              dense={true}
                              disableImport={true}
                              file={file.node}
                              nested={true}
                              isExternalReferenceAttachment={isFileAttached}
                            />
                            ),
                          )}
                        </List>
                    )}
                  </React.Fragment>
                );
              })}
          </List>
          ) : (
            <div
              style={{
                display: 'table',
                height: '100%',
                width: '100%',
                paddingTop: 15,
                paddingBottom: 15,
              }}
            >
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t_i18n('No entities of this type has been found.')}
              </span>
            </div>
          )}
        {expandable && (
          <Button
            variant="contained"
            size="small"
            onClick={handleToggleExpand}
            classes={{ root: classes.buttonExpand }}
          >
            {expanded ? (
              <ExpandLessOutlined fontSize="small" />
            ) : (
              <ExpandMoreOutlined fontSize="small" />
            )}
          </Button>
        )}
      </Paper>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDialog}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDialog}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to remove this external reference?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog} disabled={removing}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={handleRemoval} disabled={removing}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayExternalLink}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseExternalLink}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to browse this external link?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseExternalLink}>{t_i18n('Cancel')}</Button>
          <Button color="secondary" onClick={handleBrowseExternalLink}>
            {t_i18n('Browse the link')}
          </Button>
        </DialogActions>
      </Dialog>
      <Formik
        enableReinitialize={true}
        initialValues={{ connector_id: '' }}
        validationSchema={importValidation(t_i18n)}
        onSubmit={onSubmitImport}
        onReset={handleCloseImport}
      >
        {({ submitForm, handleReset, isSubmitting }) => (
          <Form style={{ margin: '0 0 20px 0' }}>
            <Dialog
              PaperProps={{ elevation: 1 }}
              open={!!fileToImport}
              keepMounted={true}
              onClose={handleCloseImport}
              fullWidth={true}
            >
              <DialogTitle>{t_i18n('Launch an import')}</DialogTitle>
              <DialogContent>
                <Field
                  component={SelectField}
                  name="connector_id"
                  label={t_i18n('Connector')}
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                >
                  {data.connectorsForImport?.map((connector, i) => {
                    const disabled = !fileToImport
                      || (connector
                        && connector.connector_scope
                        && connector.connector_scope.length > 0
                        && !includes(
                          fileToImport.metaData?.mimetype,
                          connector.connector_scope,
                        ));
                    return (
                      <MenuItem
                        key={i}
                        value={connector?.id}
                        disabled={disabled || !connector?.active}
                      >
                        {connector?.name}
                      </MenuItem>
                    );
                  })}
                </Field>
              </DialogContent>
              <DialogActions>
                <Button onClick={handleReset} disabled={isSubmitting}>
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                >
                  {t_i18n('Create')}
                </Button>
              </DialogActions>
            </Dialog>
          </Form>
        )}
      </Formik>
    </div>
  );
};

export const stixCoreObjectExternalReferencesLinesQuery = graphql`
  query StixCoreObjectExternalReferencesLinesQuery($count: Int, $id: String!) {
    ...StixCoreObjectExternalReferencesLines_data
      @arguments(count: $count, id: $id)
  }
`;

const StixCoreObjectExternalReferencesLines = createPaginationContainer(
  StixCoreObjectExternalReferencesLinesContainer,
  {
    data: graphql`
      fragment StixCoreObjectExternalReferencesLines_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        id: { type: "String!" }
      ) {
        stixCoreObject(id: $id) {
          id
          externalReferences(first: $count)
            @connection(key: "Pagination_externalReferences") {
            edges {
              node {
                id
                source_name
                description
                url
                hash
                entity_type
                external_id
                fileId
                jobs(first: 100) {
                  id
                  timestamp
                  connector {
                    id
                    name
                  }
                  messages {
                    timestamp
                    message
                  }
                  errors {
                    timestamp
                    message
                  }
                  status
                }
                connectors(onlyAlive: false) {
                  id
                  connector_type
                  name
                  active
                  updated_at
                }
                importFiles(first: 500) {
                  edges {
                    node {
                      id
                      lastModified
                      ...FileLine_file
                      metaData {
                        mimetype
                        external_reference_id
                      }
                    }
                  }
                }
              }
            }
          }
        }
        connectorsForImport {
          id
          name
          active
          connector_scope
          updated_at
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixCoreObject?.externalReferences;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count }, fragmentVariables) {
      return {
        count,
        id: fragmentVariables.id,
      };
    },
    query: stixCoreObjectExternalReferencesLinesQuery,
  },
);

export default StixCoreObjectExternalReferencesLines;
