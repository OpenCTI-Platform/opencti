import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import SwitchField from '../../../../components/fields/SwitchField';
import { FieldOption } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { FintelDesignEditionOverview_fintelDesign$key } from './__generated__/FintelDesignEditionOverview_fintelDesign.graphql';
import FintelDesignReplaceDefaultDialog from './FintelDesignReplaceDefaultDialog';
import { fetchQuery, handleError } from '../../../../relay/environment';

const fintelDesignEditionPatchMutation = graphql`
  mutation FintelDesignEditionOverviewFieldPatchMutation($id: ID!, $input: [EditInput!]) {
    fintelDesignFieldPatch(id: $id, input: $input) {
      ...FintelDesignEditionOverview_fintelDesign
      ...FintelDesign_fintelDesign
    }
  }
`;

const fintelDesignOverviewFragment = graphql`
  fragment FintelDesignEditionOverview_fintelDesign on FintelDesign {
    id
    name
    description
    default
  }
`;

interface FintelDesignEditionOverviewProps {
  data: FintelDesignEditionOverview_fintelDesign$key;
  enableReferences?: boolean;
}

interface FintelDesignEditionFormValues {
  name: string;
  description: string | null;
  default: boolean;
  message?: string;
  references?: FieldOption[];
}

const FintelDesignEditionOverviewComponent: FunctionComponent<
  FintelDesignEditionOverviewProps
> = ({ data }) => {
  const { t_i18n } = useFormatter();
  const fintelDesign = useFragment(fintelDesignOverviewFragment, data);
  const typedFintelDesign = fintelDesign as typeof fintelDesign & { default?: boolean };
  const [commit] = useApiMutation(fintelDesignEditionPatchMutation);
  const [replaceDialogOpen, setReplaceDialogOpen] = useState(false);
  const [currentDefaultName, setCurrentDefaultName] = useState<string | undefined>(undefined);
  const [pendingDefaultValue, setPendingDefaultValue] = useState<FieldOption | string | undefined>(undefined);

  const fintelDesignsRefetchQuery = graphql`
    query FintelDesignEditionOverviewCurrentDefaultQuery {
      fintelDesigns(orderBy: name, orderMode: asc) {
        edges {
          node {
            id
            name
            default
          }
        }
      }
    }
  `;

  const fintelDesignValidation = () => Yup.object().shape({
    name: Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters')),
    description: Yup.string().nullable(),
  });

  const patchField = (name: string, value: FieldOption | string) => {
    commit({
      variables: {
        id: fintelDesign.id,
        input: { key: name, value: value ?? '' },
      },
    });
  };

  const isTruthyDefault = (value: unknown) => {
    if (typeof value === 'string') {
      return value === 'true';
    }
    return value === true;
  };

  const handleSubmitField = (name: string, value: FieldOption | string) => {
    if (name !== 'default' || !isTruthyDefault(value)) {
      patchField(name, value);
      return;
    }
    fetchQuery(fintelDesignsRefetchQuery, {}).toPromise()
      .then((res) => {
        const typedResult = res as {
          fintelDesigns?: {
            edges?: Array<{ node?: { id: string; name: string; default?: boolean } | null } | null>;
          };
        } | undefined;
        const existingDefault = typedResult?.fintelDesigns?.edges
          ?.map((edge) => edge?.node)
          .find((node) => node?.default && node.id !== fintelDesign.id);
        if (existingDefault?.name) {
          setCurrentDefaultName(existingDefault.name);
          setPendingDefaultValue(value);
          setReplaceDialogOpen(true);
        } else {
          patchField(name, value);
        }
      })
      .catch((error) => {
        handleError(error as Error);
      });
  };
  const initialValues: FintelDesignEditionFormValues = {
    name: fintelDesign.name,
    description: fintelDesign.description ?? '',
    default: !!typedFintelDesign.default,
  };
  return (
    <>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validateOnChange={true}
        validateOnBlur={true}
        validationSchema={fintelDesignValidation}
        onSubmit={() => {}}
      >
        {() => (
          <Form>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
              onSubmit={handleSubmitField}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
              onSubmit={handleSubmitField}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="default"
              label={t_i18n('Set as default')}
              containerstyle={{ marginTop: 20 }}
              onChange={handleSubmitField}
            />
          </Form>
        )}
      </Formik>

      <FintelDesignReplaceDefaultDialog
        open={replaceDialogOpen}
        onClose={() => {
          setReplaceDialogOpen(false);
          setPendingDefaultValue(undefined);
        }}
        onConfirm={() => {
          if (pendingDefaultValue !== undefined) {
            patchField('default', pendingDefaultValue);
          }
          setReplaceDialogOpen(false);
          setPendingDefaultValue(undefined);
        }}
        currentDefaultName={currentDefaultName ?? ''}
      />
    </>
  );
};

export default FintelDesignEditionOverviewComponent;
