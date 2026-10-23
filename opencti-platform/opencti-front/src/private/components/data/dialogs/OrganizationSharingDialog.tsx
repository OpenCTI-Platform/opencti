import React, { useState } from 'react';
import { graphql } from 'react-relay';
import DialogActions from '@mui/material/DialogActions';
import { AddOutlined } from '@mui/icons-material';
import {
  Combobox,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
  IconButton as FdsIconButton,
  Tooltip as FdsTooltip,
  TooltipContent,
  TooltipTrigger,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import StixDomainObjectCreation from '../../common/stix_domain_objects/StixDomainObjectCreation';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import { OrganizationSharingDialogOrganizationsQuery$data } from './__generated__/OrganizationSharingDialogOrganizationsQuery.graphql';

const organizationSharingDialogOrganizationsQuery = graphql`
  query OrganizationSharingDialogOrganizationsQuery($search: String) {
    organizations(search: $search) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

export interface OrganizationOption {
  label: string;
  value: string;
  type: string;
}

export const fetchOrganizationOptions = async (search: string): Promise<OrganizationOption[]> => {
  const data = await fetchQuery(organizationSharingDialogOrganizationsQuery, { search })
    .toPromise() as OrganizationSharingDialogOrganizationsQuery$data;
  return (data.organizations?.edges ?? [])
    .map(({ node }) => ({
      label: node.representative.main,
      type: node.entity_type,
      value: node.id,
    }))
    .sort((a, b) => a.label.localeCompare(b.label))
    .sort((a, b) => a.type.localeCompare(b.type));
};

export type OrganizationSharingMode = 'share' | 'unshare';

interface OrganizationSharingDialogProps {
  mode: OrganizationSharingMode;
  open: boolean;
  onClose: () => void;
  selected: OrganizationOption[];
  onSelectedChange: (organizations: OrganizationOption[]) => void;
  inputValue: string;
  onInputValueChange: (value: string) => void;
  onLaunch: (organizations: OrganizationOption[]) => void;
}

// The selection and the search text are owned by the caller: the share and unshare dialogs use the same ones
const OrganizationSharingDialog = ({
  mode,
  open,
  onClose,
  selected,
  onSelectedChange,
  inputValue,
  onInputValueChange,
  onLaunch,
}: OrganizationSharingDialogProps) => {
  const { t_i18n } = useFormatter();
  const [options, setOptions] = useState<OrganizationOption[]>([]);
  const [creationOpen, setCreationOpen] = useState(false);
  const canCreate = mode === 'share';

  const search = (value: string) => {
    onInputValueChange(value);
    fetchOrganizationOptions(value).then(setOptions);
  };

  const handleCreated = (data: { id: string; name: string; entity_type: string }) => {
    const element = { label: data.name, value: data.id, type: data.entity_type };
    setOptions((current) => [...current, element]);
    onSelectedChange([...selected, element]);
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={mode === 'share' ? t_i18n('Share with organizations') : t_i18n('Unshare with organizations')}
    >
      {canCreate && (
        <StixDomainObjectCreation
          inputValue={inputValue}
          open={creationOpen}
          display={true}
          speeddial={true}
          stixDomainObjectTypes={['Organization']}
          handleClose={() => setCreationOpen(false)}
          creationCallback={handleCreated}
        />
      )}
      <Combobox
        selectOnFocus={true}
        getOptionLabel={(option: OrganizationOption) => option.label ?? ''}
        value={selected}
        multiple={true}
        closeOnSelect
        options={options}
        inputValue={inputValue}
        onInputChange={(newValue, meta) => {
          if (meta.cause === 'type') search(newValue);
        }}
        onValueChange={(next: OrganizationOption[]) => onSelectedChange(next)}
        renderOption={(option: OrganizationOption) => (
          <>
            <div style={{ paddingTop: 4, display: 'inline-block' }}>
              <ItemIcon type={option.type} />
            </div>
            <div style={{ display: 'inline-block', flexGrow: 1, marginLeft: 10 }}>{option.label}</div>
          </>
        )}
        disableClearable
      >
        <ComboboxLabel>{t_i18n('Values')}</ComboboxLabel>
        {/* The create control is interactive, so it takes the host-owned `adornment` slot. */}
        <ComboboxField adornment={canCreate ? (
          <FdsTooltip>
            <TooltipTrigger asChild>
              <FdsIconButton
                size="sm"
                priority="tertiary"
                aria-label={t_i18n('Create organization')}
                onClick={() => setCreationOpen(true)}
                icon={<AddOutlined fontSize="small" />}
              />
            </TooltipTrigger>
            <TooltipContent>{t_i18n('Create organization')}</TooltipContent>
          </FdsTooltip>
        ) : undefined}
        >
          <ComboboxChips aria-label={t_i18n('Values')} />
          <ComboboxInput onFocus={() => search('')} />
          <ComboboxControls>
            <ComboboxClear />
            <ComboboxTrigger />
          </ComboboxControls>
        </ComboboxField>
        <ComboboxContent
          emptyMessage={t_i18n('No available options')}
          listAriaLabel={t_i18n('Values')}
        />
      </Combobox>
      <DialogActions>
        <Button variant="secondary" onClick={onClose}>
          {t_i18n('Cancel')}
        </Button>
        {mode === 'share' ? (
          <Button onClick={() => onLaunch(selected)}>
            {t_i18n('Share')}
          </Button>
        ) : (
          <Button color="secondary" onClick={() => onLaunch(selected)}>
            {t_i18n('Unshare')}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default OrganizationSharingDialog;
