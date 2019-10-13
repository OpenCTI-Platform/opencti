import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import * as PropTypes from 'prop-types';
import Tooltip from '@material-ui/core/Tooltip';
import { CheckCircle, Warning } from '@material-ui/icons';
import CircularProgress from '@material-ui/core/CircularProgress';
import React from 'react';

const FileJobComponent = ({ file }) => <React.Fragment>{
      file.jobs && file.jobs.map(job => <div key={job.id}>
          <Tooltip title={job.work_message} aria-label={job.work_message}>
         <span>
             {job.work_status === 'error'
                    && <Warning style={{ fontSize: 10, marginRight: 10, color: 'red' }}/>}
             {job.work_status === 'complete'
                    && <CheckCircle style={{ fontSize: 10, marginRight: 10, color: 'green' }}/>}
             {job.work_status === 'progress'
                    && <CircularProgress size={10} thickness={2} style={{ marginRight: 10 }} />}
         </span>
          </Tooltip>
          {job.connector.name} / {job.updated_at}
      </div>)
  }</React.Fragment>;

const FileJobFragment = createFragmentContainer(
  FileJobComponent,
  {
    file: graphql`
        fragment FileJob_file on File {
            id
            jobs {
                connector {
                    name
                }
                work_status
                work_message
                work_type
                created_at
                updated_at
            }
        }
    `,
  },
);
FileJobFragment.propTypes = {
  file: PropTypes.object.isRequired,
};

export default FileJobFragment;
