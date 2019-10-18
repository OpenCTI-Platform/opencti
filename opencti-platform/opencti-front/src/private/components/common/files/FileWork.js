import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import * as PropTypes from 'prop-types';
import { CheckCircle, Warning } from '@material-ui/icons';
import CircularProgress from '@material-ui/core/CircularProgress';
import React from 'react';

const FileWorkComponent = ({ file }) => {
  const { works } = file;
  return <React.Fragment>
      {
        works && works.map((work) => <div key={work.id}>
            <span>
              {(work.status === 'error' || work.status === 'partial')
              && <Warning style={{ fontSize: 10, marginRight: 10, color: 'red' }}/>}
              {work.status === 'complete'
              && <CheckCircle style={{ fontSize: 10, marginRight: 10, color: 'green' }}/>}
              {work.status === 'progress'
              && <CircularProgress size={10} thickness={2} style={{ marginRight: 10 }} />}
            </span>
            {work.connector.name}
        </div>)
      }
  </React.Fragment>;
};

const FileWorkFragment = createFragmentContainer(
  FileWorkComponent,
  {
    file: graphql`
        fragment FileWork_file on File {
            id
            works {
                connector {
                    name
                }
                jobs {
                    created_at
                    messages
                }
                status
                work_type
                created_at
            }
        }
    `,
  },
);
FileWorkFragment.propTypes = {
  file: PropTypes.object.isRequired,
};

export default FileWorkFragment;
