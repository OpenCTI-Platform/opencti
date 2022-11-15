import React, { FunctionComponent } from 'react';
import Slide, { SlideProps } from '@mui/material/Slide';
import makeStyles from '@mui/styles/makeStyles';
import { QueryRenderer } from '../../../relay/environment';
import WorkflowLines, { workflowLinesQuery } from './workflow/WorkflowLines';
import SearchInput from '../../../components/SearchInput';
import { saveViewParameters } from '../../../utils/ListParameters';
import WorkflowsStatusesMenu from './workflow/WorkflowsStatusesMenu';
import useLocalStorage from '../../../utils/hooks/useLocalStorage';
import { WorkflowLinesQuery$data } from './workflow/__generated__/WorkflowLinesQuery.graphql';

const Transition = React.forwardRef((props: SlideProps, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  parameters: {
    float: 'left',
    marginTop: -10,
  },
}));

const LOCAL_STORAGE_KEY = 'view-workflow';

interface WorkflowProps {
  history: History,
  location: Location,
}

const Workflow: FunctionComponent<WorkflowProps> = ({ history, location }) => {
  const classes = useStyles();

  const [viewStorage, setViewStorage] = useLocalStorage(LOCAL_STORAGE_KEY, {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: false,
    openExports: false,
  });
  const { searchTerm } = viewStorage;

  const saveView = () => {
    saveViewParameters(
      history,
      location,
      'view-workflow',
      viewStorage,
    );
  };

  const handleSearch = (value: string) => {
    setViewStorage((c) => ({ ...c, searchTerm: value }));
    saveView();
  };

  return (
    <div className={classes.container}>
      <div className={classes.parameters}>
        <div style={{ float: 'left', marginRight: 20 }}>
          <SearchInput
            variant="small"
            onSubmit={handleSearch}
            keyword={searchTerm}
          />
        </div>
      </div>
      <div className="clearfix" />
      <QueryRenderer
        query={workflowLinesQuery}
        render={({ props }: { props: WorkflowLinesQuery$data }) => {
          if (props) {
            return <WorkflowLines data={props} keyword={searchTerm ?? ''} />;
          }
          return <div />;
        }}
      />
      <WorkflowsStatusesMenu />
    </div>
  );
};

export default Workflow;
