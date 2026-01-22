const LTS_EE_MESSAGE = 'You are about to disable the "LTS Enterprise Edition". Please note that this action will prevent any usage of the platform.';

const STANDARD_EE_MESSAGE = 'You are about to disable the "Enterprise Edition" mode. Please note that this action will disable access to certain advanced features (organization segregation, automation, file indexing etc.).';

const getEEWarningMessage = (isLts: boolean): string => (isLts ? LTS_EE_MESSAGE : STANDARD_EE_MESSAGE);

export default getEEWarningMessage;
