import React, { useRef, useState } from 'react';
import * as PropTypes from 'prop-types';
import { compose, includes, map } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Select from '@material-ui/core/Select';
import MenuItem from '@material-ui/core/MenuItem';
import { CloudUpload } from '@material-ui/icons';
import IconButton from '@material-ui/core/IconButton';
import { ConnectionHandler } from 'relay-runtime';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';

const styles = theme => ({
  button: {
    marginLeft: theme.spacing(2),
  },
  rightIcon: {
    marginLeft: theme.spacing(1),
  },
  dialogActions: {
    padding: '0 17px 20px 0',
  },
});

const FileUploaderMutation = graphql`
  mutation FileUploaderMutation($input: FileUpload) {
    uploadFile(input: $input) {
      ...FileViewer_files
    }
  }
`;

const FileUploader = (props) => {
  const {
    entityId, entityType, uploadType, t, classes,
  } = props;
  const [type, setType] = useState('application/stix+json');
  const uploadRef = useRef(null);
  const handleChangeType = event => setType(event.target.value);
  const handleOpenUpload = () => uploadRef.current.click();
  const handleUpload = (file) => {
    commitMutation({
      mutation: FileUploaderMutation,
      variables: {
        input: {
          uploadType: type, file, entityId, entityType,
        },
      },
      updater: (store) => {
        const payload = store.getRootField('uploadFile');
        const newEdge = payload.setLinkedRecord(payload, 'node');
        const rootStore = store.getRoot();
        const conn = ConnectionHandler.getConnection(
          rootStore,
          'Pagination_files',
          { category: uploadType, entityId, entityType },
        );
        // Insert element only if not exists in the current listing
        const fileId = payload.getDataID();
        const edges = conn.getLinkedRecords('edges');
        const ids = map(r => r.getLinkedRecord('node').getValue('id'), edges);
        if (!includes(fileId, ids)) {
          ConnectionHandler.insertEdgeBefore(conn, newEdge);
        }
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('File successfully uploaded');
      },
    });
  };
  return <React.Fragment>
    <Select style={{ width: '200px', marginBottom: 5 }}
            name="type" label={t('Import type')}
            fullWidth={true}
            inputProps={{ name: 'type', id: 'type' }}
            onChange={handleChangeType}
            value={type}>
      <MenuItem value="application/stix+json">{t('application/stix+json')}</MenuItem>
      <MenuItem value="application/pdf">{t('application/pdf')}</MenuItem>
    </Select>
    <input ref={uploadRef} type="file" style={{ display: 'none' }}
           onChange={({ target: { validity, files: [file] } }) =>
           // eslint-disable-next-line implicit-arrow-linebreak
             validity.valid && handleUpload(file)
           }
    />
    <IconButton onClick={handleOpenUpload} aria-haspopup="true" color="primary">
      <CloudUpload className={classes.rightIcon} />
    </IconButton>
</React.Fragment>;
};

FileUploader.propTypes = {
  entityId: PropTypes.string,
  entityType: PropTypes.string,
  uploadType: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(FileUploader);
