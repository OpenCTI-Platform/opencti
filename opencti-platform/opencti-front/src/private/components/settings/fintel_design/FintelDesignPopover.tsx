import MoreVert from '@mui/icons-material/MoreVert';
import { Menu, MenuItem, PopoverProps } from '@mui/material';
import { UIEvent, useState } from 'react';
import IconButton from '@common/button/IconButton';
import { graphql } from 'relay-runtime';
import { fetchQuery, handleError } from 'src/relay/environment';
import stopEvent from '../../../../utils/domEvent';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../components/i18n';
import FintelDesignReplaceDefaultDialog from './FintelDesignReplaceDefaultDialog';

const fintelDesignSetDefaultMutation = graphql`
  mutation FintelDesignPopoverSetDefaultMutation($id: ID!, $input: [EditInput!]) {
    fintelDesignFieldPatch(id: $id, input: $input) {
      id
      default
    }
  }
`;

const fintelDesignsRefetchQuery = graphql`
  query FintelDesignPopoverRefetchQuery {
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

interface FintelDesignPopoverProps {
  fintelDesignId: string;
  isDefault: boolean;
  currentDefaultName?: string;
  inline?: boolean;
  onDelete?: () => void;
}

const FintelDesignPopover = ({
  fintelDesignId,
  isDefault,
  currentDefaultName,
  inline = true,
  onDelete,
}: FintelDesignPopoverProps) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [replaceDialogOpen, setReplaceDialogOpen] = useState(false);
  const [resolvedDefaultName, setResolvedDefaultName] = useState<string | undefined>(currentDefaultName);
  const [commitSetDefault] = useApiMutation(fintelDesignSetDefaultMutation);

  const refetchDesigns = () => {
    fetchQuery(fintelDesignsRefetchQuery, {}).toPromise().catch((err) => {
      handleError(err);
    });
  };

  const doSetDefault = () => {
    commitSetDefault({
      variables: {
        id: fintelDesignId,
        input: [{ key: 'default', value: ['true'] }],
      },
      onCompleted: refetchDesigns,
    });
  };

  const onSetAsDefault = async (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);

    if (currentDefaultName) {
      setResolvedDefaultName(currentDefaultName);
      setReplaceDialogOpen(true);
      return;
    }

    const result = await fetchQuery(fintelDesignsRefetchQuery, {}).toPromise() as {
      fintelDesigns?: {
        edges?: Array<{ node?: { id: string; name: string; default?: boolean } | null } | null>;
      };
    } | undefined;
    const existingDefault = result?.fintelDesigns?.edges
      ?.map((edge) => edge?.node)
      .find((node) => node?.default && node.id !== fintelDesignId);

    if (existingDefault?.name) {
      setResolvedDefaultName(existingDefault.name);
      setReplaceDialogOpen(true);
    } else {
      doSetDefault();
    }
  };

  const onRemoveDefault = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
    commitSetDefault({
      variables: {
        id: fintelDesignId,
        input: [{ key: 'default', value: ['false'] }],
      },
      onCompleted: refetchDesigns,
    });
  };

  const onDeleteClick = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
    onDelete?.();
  };

  return (
    <>
      {inline ? (
        <IconButton
          onClick={(e: UIEvent) => {
            stopEvent(e);
            setAnchorEl(e.currentTarget);
          }}
          aria-haspopup="true"
          color="primary"
        >
          <MoreVert fontSize="small" />
        </IconButton>
      ) : (
        <IconButton
          onClick={(e: UIEvent) => {
            stopEvent(e);
            setAnchorEl(e.currentTarget);
          }}
          aria-haspopup="true"
          className="icon-outlined"
          variant="secondary"
          size="default"
        >
          <MoreVert fontSize="small" />
        </IconButton>
      )}

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={(e) => {
          stopEvent(e as UIEvent);
          setAnchorEl(undefined);
        }}
      >
        {onDelete && <MenuItem onClick={onDeleteClick}>{t_i18n('Delete')}</MenuItem>}
        {isDefault
          ? <MenuItem onClick={onRemoveDefault}>{t_i18n('Remove default')}</MenuItem>
          : <MenuItem onClick={onSetAsDefault}>{t_i18n('Set as default')}</MenuItem>}
      </Menu>

      <FintelDesignReplaceDefaultDialog
        open={replaceDialogOpen}
        onClose={() => setReplaceDialogOpen(false)}
        onConfirm={() => {
          setReplaceDialogOpen(false);
          doSetDefault();
        }}
        currentDefaultName={resolvedDefaultName ?? ''}
      />
    </>
  );
};

export default FintelDesignPopover;
