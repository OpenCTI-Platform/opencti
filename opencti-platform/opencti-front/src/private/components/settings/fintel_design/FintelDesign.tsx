import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import { FintelDesignQuery } from '@components/settings/fintel_design/__generated__/FintelDesignQuery.graphql';
import FintelDesignPopover from '@components/settings/fintel_design/FintelDesignPopover';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Paper from '@mui/material/Paper';
import * as Yup from 'yup';
import { useParams } from 'react-router-dom';
import { FintelDesign_fintelDesign$key } from '@components/settings/fintel_design/__generated__/FintelDesign_fintelDesign.graphql';
import CustomizationMenu from '@components/settings/CustomizationMenu';
import { Field, Form, Formik } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import PageContainer from '../../../../components/PageContainer';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FintelDesignQuery } from './__generated__/FintelDesignQuery.graphql';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import MarkdownField from '../../../../components/fields/MarkdownField';

const fintelDesignQuery = graphql`
  query FintelDesignQuery($id: String!) {
    fintelDesign(id: $id) {
      ...FintelDesign_fintelDesign
      ...FintelDesignsLine_node
    }
  }
`;

const fintelDesignFieldPatchMutation = graphql`
  mutation FintelDesignFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    fintelDesignFieldPatch(id: $id, input: $input) {
      id
      name
      description
      url
      gradiantFromColor
      gradiantToColor
      textColor
    }
  }
`;
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import PageContainer from '../../../../components/PageContainer';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FintelDesignQuery } from './__generated__/FintelDesignQuery.graphql';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import MarkdownField from '../../../../components/fields/MarkdownField';

const fintelDesignQuery = graphql`
  query FintelDesignQuery($id: String!) {
    fintelDesign(id: $id) {
      id
      name
      ...FintelDesign_fintelDesign
      ...FintelDesignsLine_node
    }
  }
`;

const fintelDesignFieldPatchMutation = graphql`
  mutation FintelDesignFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    fintelDesignFieldPatch(id: $id, input: $input) {
      id
      name
      description
      url
      gradiantFromColor
      gradiantToColor
      textColor
    }
  }
`;

const fintelDesignComponentFragment = graphql`
  fragment FintelDesign_fintelDesign on FintelDesign {
    id
    name
    description
    url
    gradiantFromColor
    gradiantToColor
    textColor
  }
`;

interface FintelDesignComponentProps {
  queryRef: PreloadedQuery<FintelDesignQuery>
}

const FintelDesignComponent: FunctionComponent<FintelDesignComponentProps> = ({
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const queryResult = usePreloadedQuery(fintelDesignQuery, queryRef);
  const fintelDesign = useFragment<FintelDesign_fintelDesign$key>(
    fintelDesignComponentFragment,
    queryResult.fintelDesign,
  );
  if (!fintelDesign) return null;

  const [commitFieldPatch] = useApiMutation(fintelDesignFieldPatchMutation);

  const initialValues = {
    name: fintelDesign.name,
    description: fintelDesign.description,
    url: fintelDesign.url,
    gradiantFromColor: fintelDesign.gradiantFromColor,
    gradiantToColor: fintelDesign.gradiantToColor,
    textColor: fintelDesign.textColor,
  };

  const fintelDesignValidation = Yup.object().shape({
    url: Yup.string().nullable(),
    gradiantFromColor: Yup.string().nullable(),
    gradiantToColor: Yup.string().nullable(),
    textColor: Yup.string().nullable(),
  });

  const handleFieldChange = (name: string, value: string) => {
    commitFieldPatch({
      variables: {
        id: fintelDesign.id,
        input: [{ key: name, value: (value) ?? '' }],
      },
    });
  };
  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <Typography
          variant="h1"
          gutterBottom={true}
          style={{ marginRight: 10 }}
        >
          {fintelDesign.name}
        </Typography>
        <div style={{ marginTop: -6 }}>
          <FintelDesignPopover data={fintelDesign}/>
        </div>
      </div>
      <PageContainer withRightMenu>
        <CustomizationMenu />
        <Breadcrumbs
          noMargin
          elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Customization') },
            { label: t_i18n('Fintel design'), link: '/dashboard/settings/customization/fintel_designs' },
            { label: `${fintelDesign.name}`, current: true },
          ]}
        />
        <Grid
          container={true}
          spacing={3}
          style={{ margin: 0, paddingRight: 20 }}
        >
          <Grid item xs={6} style={{ paddingLeft: 0 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t_i18n('Configuration')}
            </Typography>
            <Paper
              style={{
                marginTop: theme.spacing(1),
                padding: '15px',
                borderRadius: 6,
              }}
              variant="outlined"
            >
              <Formik
                onSubmit={() => {}}
                enableReinitialize={true}
                initialValues={initialValues}
                validationSchema={fintelDesignValidation}
                validateOnChange={true}
                validateOnBlur={true}
              >
                {() => (
                  <Form>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="name"
                      label={t_i18n('Name')}
                      fullWidth
                      onSubmit={handleFieldChange}
                    />
                    <Field
                      component={MarkdownField}
                      name="description"
                      label={t_i18n('Description')}
                      fullWidth={true}
                      multiline={true}
                      rows={2}
                      onSubmit={handleFieldChange}
                      style={fieldSpacingContainerStyle}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name="url"
                      label={t_i18n('Logo URL')}
                      fullWidth
                      onSubmit={handleFieldChange}
                      style={fieldSpacingContainerStyle}
                    />
                    <Field
                      component={ColorPickerField}
                      name="gradiantFromColor"
                      label={t_i18n('Background primary color')}
                      placeholder={t_i18n('Default')}
                      fullWidth
                      onSubmit={handleFieldChange}
                      variant="standard"
                      style={fieldSpacingContainerStyle}
                    />
                    <Field
                      component={ColorPickerField}
                      name="gradiantToColor"
                      label={t_i18n('Background secondary color')}
                      placeholder={t_i18n('Default')}
                      fullWidth
                      onSubmit={handleFieldChange}
                      variant="standard"
                      style={fieldSpacingContainerStyle}
                    />
                    <Field
                      component={ColorPickerField}
                      name="textColor"
                      label={t_i18n('Text color')}
                      placeholder={t_i18n('Default')}
                      fullWidth
                      onSubmit={handleFieldChange}
                      variant="standard"
                      style={fieldSpacingContainerStyle}
                    />
                  </Form>
                )}
              </Formik>
            </Paper>
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Preview')}
            </Typography>
            <Paper
              style={{
                marginTop: theme.spacing(1),
                padding: '15px',
                borderRadius: 6,
              }}
              variant="outlined"
            >
              <div>Preview to be added in chunk 3</div>
            </Paper>
          </Grid>
        </Grid>
      </PageContainer>
    </>
  );
};

const FintelDesign = () => {
  const { fintelDesignId }: { fintelDesignId?: string } = useParams();
  if (!fintelDesignId) return null;
  const queryRef = useQueryLoading<FintelDesignQuery>(
    fintelDesignQuery,
    { id: fintelDesignId },
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <FintelDesignComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.container} />
  );
};

export default FintelDesign;
