import React, {useState} from 'react';
import FileExportViewer from "@components/common/files/FileExportViewer";
import Drawer from "@mui/material/Drawer";
import makeStyles from "@mui/styles/makeStyles";
import {stixCoreObjectsExportsContentQuery} from "@components/common/stix_core_objects/StixCoreObjectsExportsContent";
import {commitMutation, MESSAGING$, QueryRenderer} from "../../../../relay/environment";
import relay from "vite-plugin-relay";
import {filter, map} from "ramda";
import {Value} from "classnames";
import Tooltip from "@mui/material/Tooltip";
import IconButton from "@mui/material/IconButton";
import {FileExportOutline} from "mdi-material-ui";
import Paper from "@mui/material/Paper";
import List from "@mui/material/List";
import FileLine from "@components/common/files/FileLine";
import {useFormatter} from "../../../../components/i18n";
import {AccountBalanceOutlined} from "@mui/icons-material";
import {truncate} from "../../../../utils/String";
import Chip from "@mui/material/Chip";
import ToggleButton from "@mui/material/ToggleButton";
import {DialogTitle} from "@mui/material";
import Dialog from "@mui/material/Dialog";
import {Field, Form, Formik} from "formik";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import TextField from "@mui/material/TextField";
import Button from "@mui/material/Button";
import * as Yup from "yup";
import {ConnectionHandler} from "relay-runtime";
import {fileManagerExportMutation} from "@components/common/files/FileManager";
import SelectField from "../../../../components/SelectField";
import MenuItem from "@mui/material/MenuItem";
import {fieldSpacingContainerStyle} from "../../../../utils/field";
import {markingDefinitionsLinesSearchQuery} from "@components/settings/marking_definitions/MarkingDefinitionsLines";
import Loader from "../../../../components/Loader";


const useStyles = makeStyles((theme) => ({

}));

const exportValidation = (t) => Yup.object().shape({
    format: Yup.string().required(t('This field is required')),
});

const onSubmitExport = (values, { setSubmitting, resetForm }) => {
    const maxMarkingDefinition = values.maxMarkingDefinition === 'none'
        ? null
        : values.maxMarkingDefinition;
    commitMutation({
        mutation: fileManagerExportMutation,
        variables: {
            id,
            format: values.format,
            exportType: values.type,
            maxMarkingDefinition,
        },
        updater: (store) => {
            const root = store.getRootField('stixCoreObjectEdit');
            const payloads = root.getLinkedRecords('exportAsk', {
                format: values.format,
                exportType: values.type,
                maxMarkingDefinition,
            });
            const entityPage = store.get(id);
            const conn = ConnectionHandler.getConnection(
                entityPage,
                'Pagination_exportFiles',
            );
            for (let index = 0; index < payloads.length; index += 1) {
                const payload = payloads[index];
                const newEdge = payload.setLinkedRecord(payload, 'node');
                ConnectionHandler.insertEdgeBefore(conn, newEdge);
            }
        },
        onCompleted: () => {
            setSubmitting(false);
            resetForm();
            handleCloseExport();
            MESSAGING$.notifySuccess('Export successfully started');
        },
    });
};

const StixCoreObjectFileExport = ({  entity }) => {
    console.log('StixCoreObjectFileExport', StixCoreObjectFileExport)
    const classes = useStyles();
    const { t } = useFormatter();
    const isExportPossible = true; // TODO changeMe
    const [displayFileExport, setFileExport] = useState(false);
    const handleOpenExport = () => setFileExport(true);
    const handleCloseExport = () => setFileExport(false);

    const { id, exportFiles } = entity;
    const [open, setOpen] = useState(false);
    const handleClickOpen = () => {
        setOpen(true);
    };

    return (
           <div>
               <div>
                   <Tooltip
                       title={
                           isExportPossible
                               ? t('Generate an export')
                               : t('No export connector available to generate an export')
                       }
                       aria-label="generate-export"
                   >
                       <ToggleButton
                           onClick = {handleClickOpen}
                          disabled={!isExportPossible}
                          value="quick-export"
                          aria-haspopup="true"
                          color="primary"
                          size="small"
                          style={{ marginRight: 3 }}
                      >
                            <FileExportOutline
                                fontSize="small"
                                color= "primary"
                            />
                       </ToggleButton>
                   </Tooltip>
                   <Formik
                       enableReinitialize={true}
                       initialValues={{
                           format: '',
                           maxMarkingDefinition: 'none',
                       }}
                       validationSchema={exportValidation(t)}
                       onSubmit={onSubmitExport}
                       onReset={() => setOpen(false)}
                   >
                       {({ submitForm, handleReset, isSubmitting }) => (

                           <Form>
                           <Dialog PaperProps={{ elevation: 1 }}
                                   open={open}
                                   onClose={() => setOpen(false)}
                                   fullWidth={true}>
                                <DialogTitle>{t('Generate an export')}</DialogTitle>
                               <QueryRenderer
                                   query={markingDefinitionsLinesSearchQuery}
                                   variables={{ first: 200 }}
                                   render={({ props }) => {
                                       if (props && props.markingDefinitions) {
                                           return (
                                <DialogContent>
                                    <Field
                                        component={SelectField}
                                        variant="standard"
                                        name="format"
                                        label={t('Export format')}
                                        fullWidth={true}
                                        containerstyle={{ width: '100%' }}
                                    >
                                            <MenuItem
                                            >
                                            </MenuItem>
                                    </Field>
                                    <Field
                                        component={SelectField}
                                        variant="standard"
                                        name="type"
                                        label={t('Export type')}
                                        fullWidth={true}
                                        containerstyle={fieldSpacingContainerStyle}
                                    >
                                        <MenuItem value="simple">
                                            {t('Simple export (just the entity)')}
                                        </MenuItem>
                                        <MenuItem value="full">
                                            {t('Full export (entity and first neighbours)')}
                                        </MenuItem>
                                    </Field>
                                    <Field
                                        component={SelectField}
                                        variant="standard"
                                        name="maxMarkingDefinition"
                                        label={t('Max marking definition level')}
                                        fullWidth={true}
                                        containerstyle={fieldSpacingContainerStyle}
                                    >
                                        <MenuItem value="none">{t('None')}</MenuItem>
                                        {map(
                                            (markingDefinition) => (
                                                <MenuItem
                                                    key={markingDefinition.node.id}
                                                    value={markingDefinition.node.id}
                                                >
                                                    {markingDefinition.node.definition}
                                                </MenuItem>
                                            ),
                                            props.markingDefinitions.edges,
                                        )}
                                    </Field>
                                </DialogContent>
                                           );
                                       }
                                       return <Loader variant="inElement" />;
                                   }}
                               />
                               <DialogActions>
                                   <Button onClick={handleReset} disabled={isSubmitting}>Cancel</Button>
                                   <Button
                                       color="secondary"
                                       onClick={submitForm}
                                       disabled={isSubmitting}
                                   >
                                       {t('Create')}
                                   </Button>
                               </DialogActions>
                           </Dialog>
                        </Form>
                       )}
                   </Formik>
               </div>
           </div>

        );
}

export default StixCoreObjectFileExport;