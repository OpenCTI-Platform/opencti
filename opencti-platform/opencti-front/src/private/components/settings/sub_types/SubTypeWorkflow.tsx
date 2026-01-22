import Card from '@common/card/Card';
import Grid from '@mui/material/Grid2';

const SubTypeWorkflow = () => {
  // TODO use workflow data from subType
  // const { subType } = useOutletContext<{ subType: SubTypeQuery['response']['subType'] }>();
  return (
    <Grid container spacing={3}>

      <Grid size={{ xs: 12 }} gap={3}>
        <Card>
          {/* TODO Workflow settings component */}
          <div>Workflow settings component</div>
        </Card>
      </Grid>
    </Grid>
  );
};

export default SubTypeWorkflow;
