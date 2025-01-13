import * as Yup from 'yup';
import { Option } from '@components/common/form/ReferenceField';

const ipAddrList = ['IPv4-Addr', 'IPv6-Addr'];
const observableTypeList = ['Artifact', 'Domain-Name', 'Hostname', 'Url', 'StixFile', 'Email-Addr'];
export const availableEntityTypes = [...observableTypeList, ...ipAddrList];

const entityTypeListValidator = (entityTypeList?: Option[]) => {
  if (!entityTypeList) return false;
  let containIpAddr = false;
  let containObservableType = false;
  for (let i = 0; i < entityTypeList.length; i += 1) {
    if (ipAddrList.includes(entityTypeList[i].value)) {
      containIpAddr = true;
    } else {
      containObservableType = true;
    }

    if (containIpAddr && containObservableType) return false;
  }
  return true;
};

export const exclusionListUpdateValidator = (t: (n: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  exclusion_list_entity_types: Yup.array().min(1, t('Minimum one entity type')).test(
    'entityTypeListValidator',
    t('Incompatible types, can\'t mix IP types with other types'),
    (value?: Option[]) => entityTypeListValidator(value),
  ).required(t('This field is required')),
});

export const exclusionListCreationValidator = (t: (value: string) => string, isCreatedWithFile: boolean) => {
  return Yup.object().shape({
    name: Yup.string().trim().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    exclusion_list_entity_types: Yup.array().min(1, t('Minimum one entity type')).test(
      'entityTypeListValidator',
      t('Incompatible types, can\'t mix IP types with other types'),
      (value?: Option[]) => entityTypeListValidator(value),
    ).required(t('This field is required')),
    file: isCreatedWithFile ? Yup.mixed().required(t('This field is required')) : Yup.mixed().nullable(),
    content: isCreatedWithFile ? Yup.string().nullable() : Yup.string().required(t('This field is required')),
  });
};
