import { makeStyles } from '@mui/styles';
import { FunctionComponent, useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import * as Yup from 'yup';
import * as R from 'ramda';
import { Field, Form, Formik, FormikConfig } from 'formik';
import { Button, Drawer, Fab, IconButton, Typography } from '@mui/material';
import { Add } from '@mui/icons-material';
import { Close } from 'mdi-material-ui';
import { Theme } from '../../../../components/Theme';
import { Option } from '../../common/form/ReferenceField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { insertNode } from '../../../../utils/store';
import { AccountsLinesPaginationQuery$variables } from './__generated__/AccountsLinesPaginationQuery.graphql';
import AutocompleteField from '../../../../components/AutocompleteField';
import { valToKey } from '../../../../utils/Localization';

export enum CurrencyCode {
  afghan_afghani__afn = 'afghan_afghani__afn',
  albanian_lek__all = 'albanian_lek__all',
  algerian_dinar__dzd = 'algerian_dinar__dzd',
  angolan_kwanza__aoa = 'angolan_kwanza__aoa',
  argentine_peso__ars = 'argentine_peso__ars',
  armenian_dram__amd = 'armenian_dram__amd',
  aruban_florin__awg = 'aruban_florin__awg',
  australian_dollar__aud = 'australian_dollar__aud',
  azerbaijani_manat__azn = 'azerbaijani_manat__azn',
  bahamian_dollar__bsd = 'bahamian_dollar__bsd',
  bahraini_dinar__bhd = 'bahraini_dinar__bhd',
  bangladeshi_taka__bdt = 'bangladeshi_taka__bdt',
  barbados_dollar__bbd = 'barbados_dollar__bbd',
  basic_attention_token__bat = 'basic_attention_token__bat',
  belarusian_ruble__byr = 'belarusian_ruble__byr',
  belize_dollar__bzd = 'belize_dollar__bzd',
  bermudian_dollar__bmd = 'bermudian_dollar__bmd',
  bhutanese_ngultrum__btn = 'bhutanese_ngultrum__btn',
  binance_coin__bnb = 'binance_coin__bnb',
  bitcoin__btc = 'bitcoin__btc',
  bitcoin_cash__bch = 'bitcoin_cash__bch',
  bitcoin_gold__btg = 'bitcoin_gold__btg',
  bitcoin_satoshi_vision__bsv = 'bitcoin_satoshi_vision__bsv',
  boliviano__bob = 'boliviano__bob',
  bolivian_mvdol__bov = 'bolivian_mvdol__bov',
  bosnia_and_herzegovina_convertible_mark__bam = 'bosnia_and_herzegovina_convertible_mark__bam',
  botswana_pula__bwp = 'botswana_pula__bwp',
  brazilian_real__brl = 'brazilian_real__brl',
  brunei_dollar__bnd = 'brunei_dollar__bnd',
  bulgarian_lev__bgn = 'bulgarian_lev__bgn',
  burundian_franc__bif = 'burundian_franc__bif',
  cambodian_riel__khr = 'cambodian_riel__khr',
  canadian_dollar__cad = 'canadian_dollar__cad',
  cape_verde_escudo__cve = 'cape_verde_escudo__cve',
  cardano__ada = 'cardano__ada',
  cayman_islands_dollar__kyd = 'cayman_islands_dollar__kyd',
  cfa_franc_bceao__xof = 'cfa_franc_bceao__xof',
  cfa_franc_beac__xaf = 'cfa_franc_beac__xaf',
  cfp_franc__xpf = 'cfp_franc__xpf',
  chilean_peso__clp = 'chilean_peso__clp',
  chinese_yuan__cny = 'chinese_yuan__cny',
  chinese_yuan_offshore__cnh = 'chinese_yuan_offshore__cnh',
  colombian_peso__cop = 'colombian_peso__cop',
  comoro_franc__kmf = 'comoro_franc__kmf',
  congolese_franc__cdf = 'congolese_franc__cdf',
  costa_rican_colon__crc = 'costa_rican_colon__crc',
  croatian_kuna__hrk = 'croatian_kuna__hrk',
  cuban_convertible_peso__cuc = 'cuban_convertible_peso__cuc',
  cuban_peso__cup = 'cuban_peso__cup',
  czech_koruna__czk = 'czech_koruna__czk',
  danish_krone__dkk = 'danish_krone__dkk',
  dash__dash = 'dash__dash',
  djiboutian_franc__djf = 'djiboutian_franc__djf',
  dogecoin__doge = 'dogecoin__doge',
  dominican_peso__dop = 'dominican_peso__dop',
  east_caribbean_dollar__xcd = 'east_caribbean_dollar__xcd',
  egyptian_pound__egp = 'egyptian_pound__egp',
  eritrean_nakfa__ern = 'eritrean_nakfa__ern',
  ethereum__eth = 'ethereum__eth',
  ethereum_classic__etc = 'ethereum_classic__etc',
  ethiopian_birr__etb = 'ethiopian_birr__etb',
  european_composite_unit__xba = 'european_composite_unit__xba',
  european_monetary_unit__xbb = 'european_monetary_unit__xbb',
  european_unit_of_account_17__xbd = 'european_unit_of_account_17__xbd',
  european_unit_of_account_9__xbc = 'european_unit_of_account_9__xbc',
  euro__eur = 'euro__eur',
  falkland_islands_pound__fkp = 'falkland_islands_pound__fkp',
  fiji_dollar__fjd = 'fiji_dollar__fjd',
  gambian_dalasi__gmd = 'gambian_dalasi__gmd',
  georgian_lari__gel = 'georgian_lari__gel',
  ghanaian_cedi__ghs = 'ghanaian_cedi__ghs',
  gibraltar_pound__gip = 'gibraltar_pound__gip',
  gold__xau = 'gold__xau',
  guatemalan_quetzal__gtq = 'guatemalan_quetzal__gtq',
  guinean_franc__gnf = 'guinean_franc__gnf',
  guyanese_dollar__gyd = 'guyanese_dollar__gyd',
  haitian_gourde__htg = 'haitian_gourde__htg',
  honduran_lempira__hnl = 'honduran_lempira__hnl',
  hong_kong_dollar__hkd = 'hong_kong_dollar__hkd',
  hungarian_forint__huf = 'hungarian_forint__huf',
  icelandic_krona__isk = 'icelandic_krona__isk',
  indian_rupee__inr = 'indian_rupee__inr',
  indonesian_rupiah__idr = 'indonesian_rupiah__idr',
  iranian_rial__irr = 'iranian_rial__irr',
  iraqi_dinar__iqd = 'iraqi_dinar__iqd',
  israeli_new_shekel__ils = 'israeli_new_shekel__ils',
  jamaican_dollar__jmd = 'jamaican_dollar__jmd',
  japanese_yen__jpy = 'japanese_yen__jpy',
  jordanian_dinar__jod = 'jordanian_dinar__jod',
  kazakhstani_tenge__kzt = 'kazakhstani_tenge__kzt',
  kenyan_shilling__kes = 'kenyan_shilling__kes',
  kuwaiti_dinar__kwd = 'kuwaiti_dinar__kwd',
  kyrgyzstani_som__kgs = 'kyrgyzstani_som__kgs',
  lao_kip__lak = 'lao_kip__lak',
  latvian_lats__lvl = 'latvian_lats__lvl',
  lebanese_pound__lbp = 'lebanese_pound__lbp',
  lesotho_loti__lsl = 'lesotho_loti__lsl',
  liberian_dollar__lrd = 'liberian_dollar__lrd',
  libyan_dinar__lyd = 'libyan_dinar__lyd',
  lisk__lsk = 'lisk__lsk',
  lithuanian_litas__ltl = 'lithuanian_litas__ltl',
  macanese_pataca__mop = 'macanese_pataca__mop',
  macedonian_denar__mkd = 'macedonian_denar__mkd',
  malagasy_ariary__mga = 'malagasy_ariary__mga',
  malawian_kwacha__mwk = 'malawian_kwacha__mwk',
  malaysian_ringgit__myr = 'malaysian_ringgit__myr',
  maldivian_rufiyaa__mvr = 'maldivian_rufiyaa__mvr',
  mauritanian_ouguiya__mro = 'mauritanian_ouguiya__mro',
  mauritian_rupee__mur = 'mauritian_rupee__mur',
  mexican_peso__mxn = 'mexican_peso__mxn',
  mexican_unidad_de_inversion__mxv = 'mexican_unidad_de_inversion__mxv',
  moldovan_leu__mdl = 'moldovan_leu__mdl',
  monero__xmr = 'monero__xmr',
  mongolian_tugrik__mnt = 'mongolian_tugrik__mnt',
  moroccan_dirham__mad = 'moroccan_dirham__mad',
  mozambican_metical__mzn = 'mozambican_metical__mzn',
  myanma_kyat__mmk = 'myanma_kyat__mmk',
  namibian_dollar__nad = 'namibian_dollar__nad',
  neo__neo = 'neo__neo',
  nepalese_rupee__npr = 'nepalese_rupee__npr',
  netherlands_antillean_guilder__ang = 'netherlands_antillean_guilder__ang',
  new_taiwan_dollar__twd = 'new_taiwan_dollar__twd',
  new_zealand_dollar__nzd = 'new_zealand_dollar__nzd',
  nicaraguan_cordoba__nio = 'nicaraguan_cordoba__nio',
  nigerian_naira__ngn = 'nigerian_naira__ngn',
  north_korean_won__kpw = 'north_korean_won__kpw',
  norwegian_krone__nok = 'norwegian_krone__nok',
  omani_rial__omr = 'omani_rial__omr',
  omisego__omg = 'omisego__omg',
  pakistani_rupee__pkr = 'pakistani_rupee__pkr',
  palladium__xpd = 'palladium__xpd',
  panamanian_balboa__pab = 'panamanian_balboa__pab',
  papua_new_guinean_kina__pgk = 'papua_new_guinean_kina__pgk',
  paraguayan_guarani__pyg = 'paraguayan_guarani__pyg',
  pence_sterling_british_penny__gbx = 'pence_sterling_british_penny__gbx',
  peruvian_nuevo_sol__pen = 'peruvian_nuevo_sol__pen',
  philippine_peso__php = 'philippine_peso__php',
  platinum__xpt = 'platinum__xpt',
  polish_z_oty__pln = 'polish_z_oty__pln',
  pound_sterling__gbp = 'pound_sterling__gbp',
  qatari_riyal__qar = 'qatari_riyal__qar',
  qtum__qtum = 'qtum__qtum',
  ripple__xrp = 'ripple__xrp',
  romanian_new_leu__ron = 'romanian_new_leu__ron',
  russian_rouble__rub = 'russian_rouble__rub',
  rwandan_franc__rwf = 'rwandan_franc__rwf',
  saint_helena_pound__shp = 'saint_helena_pound__shp',
  samoan_tala__wst = 'samoan_tala__wst',
  sao_tome_and_principe_dobra__std = 'sao_tome_and_principe_dobra__std',
  saudi_riyal__sar = 'saudi_riyal__sar',
  serbian_dinar__rsd = 'serbian_dinar__rsd',
  seychelles_rupee__scr = 'seychelles_rupee__scr',
  sierra_leonean_leone__sll = 'sierra_leonean_leone__sll',
  silver__xag = 'silver__xag',
  singapore_dollar__sgd = 'singapore_dollar__sgd',
  solomon_islands_dollar__sbd = 'solomon_islands_dollar__sbd',
  somali_shilling__sos = 'somali_shilling__sos',
  south_african_rand__zar = 'south_african_rand__zar',
  south_korean_won__krw = 'south_korean_won__krw',
  south_sudanese_pound__ssp = 'south_sudanese_pound__ssp',
  special_drawing_rights__xdr = 'special_drawing_rights__xdr',
  sri_lankan_rupee__lkr = 'sri_lankan_rupee__lkr',
  stellar_lumen__xlm = 'stellar_lumen__xlm',
  sudanese_pound__sdg = 'sudanese_pound__sdg',
  surinamese_dollar__srd = 'surinamese_dollar__srd',
  swazi_lilangeni__szl = 'swazi_lilangeni__szl',
  swedish_krona_kronor__sek = 'swedish_krona_kronor__sek',
  swiss_franc__chf = 'swiss_franc__chf',
  syrian_pound__syp = 'syrian_pound__syp',
  tajikistani_somoni__tjs = 'tajikistani_somoni__tjs',
  tanzanian_shilling__tzs = 'tanzanian_shilling__tzs',
  tehterus__usdt = 'tehterus__usdt',
  thai_baht__thb = 'thai_baht__thb',
  tongan_paanga__top = 'tongan_paanga__top',
  trinidad_and_tobago_dollar__ttd = 'trinidad_and_tobago_dollar__ttd',
  tunisian_dinar__tnd = 'tunisian_dinar__tnd',
  turkish_lira__try = 'turkish_lira__try',
  turkmenistani_manat__tmt = 'turkmenistani_manat__tmt',
  ugandan_shilling__ugx = 'ugandan_shilling__ugx',
  uic_franc__xfu = 'uic_franc__xfu',
  ukrainian_hryvnia__uah = 'ukrainian_hryvnia__uah',
  unidad_de_fomento__clf = 'unidad_de_fomento__clf',
  unidad_de_valor_real__cou = 'unidad_de_valor_real__cou',
  united_arab_emirates_dirham__aed = 'united_arab_emirates_dirham__aed',
  united_states_dollar__usd = 'united_states_dollar__usd',
  uruguayan_peso__uyu = 'uruguayan_peso__uyu',
  uruguay_peso_en_unidades_indexadas__uyi = 'uruguay_peso_en_unidades_indexadas__uyi',
  uzbekistan_som__uzs = 'uzbekistan_som__uzs',
  vanuatu_vatu__vuv = 'vanuatu_vatu__vuv',
  venezuelan_bolivar_fuerte__vef = 'venezuelan_bolivar_fuerte__vef',
  vietnamese_dong__vnd = 'vietnamese_dong__vnd',
  wir_euro__che = 'wir_euro__che',
  wir_franc__chw = 'wir_franc__chw',
  yemeni_rial__yer = 'yemeni_rial__yer',
  zambian_kwacha__zmw = 'zambian_kwacha__zmw',
  zcash__zec = 'zcash__zec',
}
export enum FinancialAccountStatus {
  active = 'Active',
  inactive = 'Inactive',
  on_hold = 'On hold',
}
export enum FinancialAccountType {
  credit_credit_card = 'Credit card',
  depository_cash_management = 'Cash management',
  depository_certificate_of_deposit_cd = 'Certificate of deposit (CD)',
  depository_checking = 'Checking',
  depository_electronic_benefit_transfer_ebt = 'Electronic benefit transfer (EBT)',
  depository_health_savings_account_hsa = 'Health Savings Account (Depository) (HSA)',
  depository_money_market = 'Money market',
  depository_prepaid_debit_card = 'Prepaid debit card',
  depository_savings = 'Savings',
  digital_wallet = 'Digital Wallet',
  investment_401a = '401a',
  investment_401k = '401k',
  investment_403b = '403b',
  investment_457b = '457b',
  investment_529 = '529',
  investment_brokerage = 'Brokerage',
  investment_cash_individual_savings_account_isa = 'Cash individual savings account (ISA)',
  investment_education_savings_account = 'Education savings account',
  investment_fixed_annuity = 'Fixed annuity',
  investment_guaranteed_investment_certificate_gic = 'Guaranteed investment certificate (GIC)',
  investment_health_reimbursement_arrangement = 'Health reimbursement arrangement',
  investment_health_savings_account_hsa = 'Health savings account (Investment) (HSA)',
  investment_individual_retirement_account_ira = 'Individual retirement account (IRA)',
  investment_individual_savings_account_isa = 'Individual savings account (ISA)',
  investment_keogh = 'Keogh',
  investment_life_income_fund_lif = 'Life income fund (LIF)',
  investment_life_insurance = 'Life insurance',
  investment_locked_in_retirement_account_lira = 'Locked-in-retirement account (LIRA)',
  investment_locked_in_retirement_income_fund_lrif = 'Locked-in-retirement income fund (LRIF)',
  investment_locked_in_retirement_savings_plan_lrsp = 'Locked-in-retirement savings plan (LRSP)',
  investment_mutual_fund = 'Mutual fund',
  investment_non_taxable_brokerage_account = 'Non-taxable brokerage account',
  investment_other_annuity = 'Other annuity',
  investment_other_insurance = 'Other insurance',
  investment_other = 'Other Investment',
  investment_pension = 'Pension',
  investment_prescribed_registered_retirement_income_fund_prif = 'Prescribed registered retirement income fund (PRIF)',
  investment_profit_sharing_plan = 'Profit sharing plan',
  investment_qualifying_share_account_qshr = 'Qualifying share account (QSHR)',
  investment_registered_disability_savings_plan_rdsp = 'Registered disability savings plan (RDSP)',
  investment_registered_education_savings_plan_resp = 'Registered education savings plan (RESP)',
  investment_registered_retirement_income_fund_rrif = 'Registered retirement income fund (RRIF)',
  investment_registered_retirement_savings_plan_rrsp = 'Registered retirement savings plan (RRSP)',
  investment_restricted_life_income_fund_rlif = 'Restricted life income fund (RLIF)',
  investment_retirement = 'Retirement',
  investment_roth_401k = 'Roth 401k',
  investment_roth = 'Roth',
  investment_salary_reduction_simplified_employee_pension_plan_sarsep = 'Salary reduction simplified employee pension plan (SARSEP)',
  investment_self_invested_personal_pension_sipp = 'Self-invested personal pension (SIPP)',
  investment_simple_individual_retirement_account_ira = 'Simple individual retirement account (IRA)',
  investment_simplified_employee_pension_sep_individual_retirement_account_ira = 'Simplified employee pension (SEP) individual retirement account (IRA)',
  investment_stock_plan = 'Stock plan',
  investment_tax_free_savings_account_tfsa = 'Tax free savings account (TFSA)',
  investment_thrift_savings_plan = 'Thrift savings plan (TSP)',
  investment_trust = 'Trust',
  investment_uniform_gift_to_minors_act_ugma = 'Uniform gift to minors act (UGMA)',
  investment_uniform_transfers_to_minors_act_utma = 'Uniform transfers to minors act (UTMA)',
  investment_variable_annuity = 'Variable annuity',
  loan_auto = 'Auto loan',
  loan_business = 'Business loan',
  loan_commercial = 'Commercial loan',
  loan_construction = 'Construction loan',
  loan_consumer = 'Consumer loan',
  loan_home_equity = 'Home equity loan',
  loan_line_of_credit = 'Line of credit',
  loan_loan = 'Loan',
  loan_mortgage = 'Mortgage',
  loan_other = 'Other loan',
  loan_overdraft = 'Overdraft',
  loan_student = 'Student loan',
  payroll = 'Payroll',
  recurring = 'Recurring',
  rewards = 'Rewards',
  safe_deposit = 'Safe deposit',
  virtual_currency = 'Virtual currency',
}

/**
 * Takes some currency code formatted ([a-z]+_)+_[a-z]{3,} and converts to
 * capitalized and spaced, with abbreviation in parentheses.
 *
 * e.g. brazilian_real__brl => Brazilian Real (BRL)
 *
 * @param currency_code Some value of the CurrencyCode enum
 * @returns Formatted currency code
 */
export function displayCurrencyCode(currency_code: CurrencyCode | string) {
  const formatted = currency_code.toString()
    .replace('__', ' (').replaceAll('_', ' ').concat(')');
  const words = formatted.split(' ').map((word) => word[0].toUpperCase() + word.substring(1));
  words[words.length - 1] = words[words.length - 1].toUpperCase();
  return words.join(' ');
}

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

const accountMutation = graphql`
  mutation AccountCreationMutation($input: FinancialAccountAddInput!) {
    financialAccountAdd(input: $input) {
      id
      name
      entity_type
      ...AccountLine_node
    }
  }
`;

interface FinancialAccountBalance {
  as_of_date: Date,
  balance: number,
}

interface AccountAddInput {
  currency_code: CurrencyCode
  name: string
  financial_account_number: string
  financial_account_status: string
  financial_account_type: string
  financial_account_balances: FinancialAccountBalance[]
  international_bank_account_number: string
  createdBy: Option | undefined
  objectMarking: Option[]
  objectLabel: Option[]
  externalReferences: Option[]
}

interface AccountFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void
  onReset?: () => void
  onCompleted?: () => void
  defaultCreatedBy?: Option
  defaultMarkingDefinitions?: Option[]
}

export function getAccountValidator(t: (message: string) => string) {
  const basicShape = {
    currency_code: Yup.mixed<CurrencyCode>()
      .oneOf(Object.values(CurrencyCode)),
    name: Yup.string()
      .min(2, 'Account must be at least 2 characters')
      .required(t('This field is required')),
    financial_account_number: Yup.string(),
    financial_account_status: Yup.mixed<string>()
      .oneOf(Object.keys(FinancialAccountStatus)),
    financial_account_type: Yup.mixed<string>()
      .oneOf(Object.keys(FinancialAccountType)),
    financial_account_balances: Yup.array().of(
      Yup.object().shape({ as_of_date: Yup.date(), balance: Yup.number() }),
    ),
    international_bank_account_number: Yup.string(),
  };
  return Yup.object().shape(basicShape);
}

export const AccountCreationForm: FunctionComponent<AccountFormProps> = ({ updater, onReset, onCompleted, defaultCreatedBy, defaultMarkingDefinitions }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const accountValidator = getAccountValidator(t);
  const [commit] = useMutation(accountMutation);

  const onSubmit: FormikConfig<AccountAddInput>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    const finalValues = R.pipe(
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('objectLabel', R.pluck('value', values.objectLabel)),
      R.assoc('externalReferences', R.pluck('value', values.externalReferences)),
    )(values);
    commit({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'financialAccountAdd');
        }
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };
  return <Formik<AccountAddInput>
      initialValues={{
        currency_code: CurrencyCode.united_states_dollar__usd,
        name: '',
        financial_account_number: '',
        financial_account_status: Object.keys(FinancialAccountStatus)[0],
        financial_account_type: Object.keys(FinancialAccountType)[0],
        financial_account_balances: [],
        international_bank_account_number: '',
        createdBy: defaultCreatedBy ?? undefined,
        objectMarking: defaultMarkingDefinitions ?? [],
        objectLabel: [],
        externalReferences: [],
      }}
      validationSchema={accountValidator}
      onSubmit={onSubmit}
      onReset={onReset}>
    {({
      submitForm,
      handleReset,
      isSubmitting,
      setFieldValue,
      values,
    }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Account Name')}
              fullWidth={true}
              detectDuplicate={['Financial-Account']}
          />
          <Field
              component={TextField}
              variant="standard"
              name="financial_account_number"
              label={t('Account Number')}
              fullWidth={true}
          />
          <Field
              component={TextField}
              variant="standard"
              name="international_bank_account_number"
              label={t('International Bank Account Number')}
              fullWidth={true}
          />
          <Field
            component={AutocompleteField}
            name={'currency_code'}
            multiple={false}
            style={{ margin: '20px 0 0 0' }}
            textfieldprops={{
              variant: 'standard',
              label: t('Currency Code'),
            }}
            noOptionsText={t('No available options')}
            options={Object.values(CurrencyCode)}
            value={displayCurrencyCode(values?.currency_code || t('Unknown'))}
            renderOption={(props: React.HTMLAttributes<HTMLLIElement>, option: string) => (
              <li {...props}> {displayCurrencyCode(option)} </li>
            )}
          />
          <Field
            component={AutocompleteField}
            name={'financial_account_status'}
            multiple={false}
            style={{ margin: '20px 0 0 0' }}
            textfieldprops={{
              variant: 'standard',
              label: t('Account Status'),
            }}
            noOptionsText={t('No available options')}
            options={Object.entries(FinancialAccountStatus)}
            value={t(valToKey(values?.financial_account_status, FinancialAccountStatus))}
            renderOption={(props: React.HTMLAttributes<HTMLLIElement>, [_, value]: [string, string]) => (
              <li {...props}> {t(value)} </li>
            )}
            onChange={(field: string, [key]: [string]) => setFieldValue(field, key) }
          />
          <Field
            component={AutocompleteField}
            name={'financial_account_type'}
            multiple={false}
            style={{ margin: '20px 0 0 0' }}
            textfieldprops={{
              variant: 'standard',
              label: t('Account Type'),
            }}
            noOptionsText={t('No available options')}
            options={Object.entries(FinancialAccountType)}
            value={t(valToKey(values?.financial_account_type, FinancialAccountType))}
            renderOption={(props: React.HTMLAttributes<HTMLLIElement>, [_, value]: [string, string]) => (
              <li {...props}> {t(value)} </li>
            )}
            onChange={(field: string, [key]: [string]) => setFieldValue(field, key) }
          />
          <CreatedByField
            name="createdBy"
            style={{
              marginTop: 20,
              width: '100%',
            }}
            setFieldValue={setFieldValue}
          />
          <ObjectLabelField
            name="objectLabel"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values?.objectLabel}
          />
          <ObjectMarkingField
            name="objectMarking"
            style={{
              marginTop: 20,
              width: '100%',
            }}
          />
          <ExternalReferencesField
            name="externalReferences"
            style={fieldSpacingContainerStyle}
            setFieldValue={setFieldValue}
            values={values?.externalReferences}
          />
          <div className={classes.buttons}>
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Create')}
            </Button>
          </div>
        </Form>
    )}
  </Formik>;
};

const AccountCreation = ({ paginationOptions }: { paginationOptions: AccountsLinesPaginationQuery$variables }) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const [open, setOpen] = useState<boolean>(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_financialAccounts',
    paginationOptions,
    'financialAccountAdd',
  );

  return (
    <div>
      <Fab onClick={handleOpen}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}>
        <Add />
      </Fab>
      <Drawer open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}>
        <div className={classes.header}>
          <IconButton aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
            color="primary">
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Create a financial account')}</Typography>
        </div>
        <div className={classes.container}>
          <AccountCreationForm updater={updater} onCompleted={handleClose} onReset={handleClose}/>
        </div>
      </Drawer>
    </div>
  );
};

export default AccountCreation;
