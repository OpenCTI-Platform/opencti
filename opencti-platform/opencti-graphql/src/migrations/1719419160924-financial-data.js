import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_STIX_CYBER_OBSERVABLES, READ_INDEX_HISTORY, READ_INDEX_STIX_META_RELATIONSHIPS, READ_INDEX_STIX_CORE_RELATIONSHIPS } from '../database/utils';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { SYSTEM_USER, executionContext } from '../utils/access';

const newVocabularies = {
  currency_code_ov: [
    { key: '0x_(zrx)' },
    { key: 'afghan_afghani_(afn)' },
    { key: 'albanian_lek_(all)' },
    { key: 'algerian_dinar_(dzd)' },
    { key: 'angolan_kwanza_(aoa)' },
    { key: 'argentine_peso_(ars)' },
    { key: 'armenian_dram_(amd)' },
    { key: 'aruban_florin_(awg)' },
    { key: 'australian_dollar_(aud)' },
    { key: 'azerbaijani_manat_(azn)' },
    { key: 'bahamian_dollar_(bsd)' },
    { key: 'bahraini_dinar_(bhd)' },
    { key: 'bangladeshi_taka_(bdt)' },
    { key: 'barbados_dollar_(bbd)' },
    { key: 'basic_attention_token_(bat)' },
    { key: 'belarusian_ruble_(byr)' },
    { key: 'belize_dollar_(bzd)' },
    { key: 'bermudian_dollar_(bmd)' },
    { key: 'bhutanese_ngultrum_(btn)' },
    { key: 'binance_coin_(bnb)' },
    { key: 'bitcoin_(btc)' },
    { key: 'bitcoin_cash_(bch)' },
    { key: 'bitcoin_gold_(btg)' },
    { key: 'bitcoin_satoshi_vision_(bsv)' },
    { key: 'boliviano_(bob)' },
    { key: 'bolivian_mvdol_(bov)' },
    { key: 'bosnia_and_herzegovina_convertible_mark_(bam)' },
    { key: 'botswana_pula_(bwp)' },
    { key: 'brazilian_real_(brl)' },
    { key: 'brunei_dollar_(bnd)' },
    { key: 'bulgarian_lev_(bgn)' },
    { key: 'burundian_franc_(bif)' },
    { key: 'cambodian_riel_(khr)' },
    { key: 'canadian_dollar_(cad)' },
    { key: 'cape_verde_escudo_(cve)' },
    { key: 'cardano_(ada)' },
    { key: 'cayman_islands_dollar_(kyd)' },
    { key: 'cfa_franc_bceao_(xof)' },
    { key: 'cfa_franc_beac_(xaf)' },
    { key: 'cfp_franc_(xpf)' },
    { key: 'chilean_peso_(clp)' },
    { key: 'chinese_yuan_(cny)' },
    { key: 'chinese_yuan_offshore_(cnh)' },
    { key: 'colombian_peso_(cop)' },
    { key: 'comoro_franc_(kmf)' },
    { key: 'congolese_franc_(cdf)' },
    { key: 'costa_rican_colon_(crc)' },
    { key: 'croatian_kuna_(hrk)' },
    { key: 'cuban_convertible_peso_(cuc)' },
    { key: 'cuban_peso_(cup)' },
    { key: 'czech_koruna_(czk)' },
    { key: 'danish_krone_(dkk)' },
    { key: 'dash_(dash)' },
    { key: 'djiboutian_franc_(djf)' },
    { key: 'dogecoin_(doge)' },
    { key: 'dominican_peso_(dop)' },
    { key: 'east_caribbean_dollar_(xcd)' },
    { key: 'egyptian_pound_(egp)' },
    { key: 'eritrean_nakfa_(ern)' },
    { key: 'ethereum_(eth)' },
    { key: 'ethereum_classic_(etc)' },
    { key: 'ethiopian_birr_(etb)' },
    { key: 'european_composite_unit_(xba)' },
    { key: 'european_monetary_unit_(xbb)' },
    { key: 'european_unit_of_account_17_(xbd)' },
    { key: 'european_unit_of_account_9_(xbc)' },
    { key: 'euro_(eur)' },
    { key: 'falkland_islands_pound_(fkp)' },
    { key: 'fiji_dollar_(fjd)' },
    { key: 'gambian_dalasi_(gmd)' },
    { key: 'georgian_lari_(gel)' },
    { key: 'ghanaian_cedi_(ghs)' },
    { key: 'gibraltar_pound_(gip)' },
    { key: 'gold_(xau)' },
    { key: 'guatemalan_quetzal_(gtq)' },
    { key: 'guinean_franc_(gnf)' },
    { key: 'guyanese_dollar_(gyd)' },
    { key: 'haitian_gourde_(htg)' },
    { key: 'honduran_lempira_(hnl)' },
    { key: 'hong_kong_dollar_(hkd)' },
    { key: 'hungarian_forint_(huf)' },
    { key: 'icelandic_krona_(isk)' },
    { key: 'indian_rupee_(inr)' },
    { key: 'indonesian_rupiah_(idr)' },
    { key: 'iranian_rial_(irr)' },
    { key: 'iraqi_dinar_(iqd)' },
    { key: 'israeli_new_shekel_(ils)' },
    { key: 'jamaican_dollar_(jmd)' },
    { key: 'japanese_yen_(jpy)' },
    { key: 'jordanian_dinar_(jod)' },
    { key: 'kazakhstani_tenge_(kzt)' },
    { key: 'kenyan_shilling_(kes)' },
    { key: 'kuwaiti_dinar_(kwd)' },
    { key: 'kyrgyzstani_som_(kgs)' },
    { key: 'lao_kip_(lak)' },
    { key: 'latvian_lats_(lvl)' },
    { key: 'lebanese_pound_(lbp)' },
    { key: 'lesotho_loti_(lsl)' },
    { key: 'liberian_dollar_(lrd)' },
    { key: 'libyan_dinar_(lyd)' },
    { key: 'lisk_(lsk)' },
    { key: 'lithuanian_litas_(ltl)' },
    { key: 'macanese_pataca_(mop)' },
    { key: 'macedonian_denar_(mkd)' },
    { key: 'malagasy_ariary_(mga)' },
    { key: 'malawian_kwacha_(mwk)' },
    { key: 'malaysian_ringgit_(myr)' },
    { key: 'maldivian_rufiyaa_(mvr)' },
    { key: 'mauritanian_ouguiya_(mro)' },
    { key: 'mauritian_rupee_(mur)' },
    { key: 'mexican_peso_(mxn)' },
    { key: 'mexican_unidad_de_inversion_(mxv)' },
    { key: 'moldovan_leu_(mdl)' },
    { key: 'monero_(xmr)' },
    { key: 'mongolian_tugrik_(mnt)' },
    { key: 'moroccan_dirham_(mad)' },
    { key: 'mozambican_metical_(mzn)' },
    { key: 'myanma_kyat_(mmk)' },
    { key: 'namibian_dollar_(nad)' },
    { key: 'neo_(neo)' },
    { key: 'nepalese_rupee_(npr)' },
    { key: 'netherlands_antillean_guilder_(ang)' },
    { key: 'new_taiwan_dollar_(twd)' },
    { key: 'new_zealand_dollar_(nzd)' },
    { key: 'nicaraguan_cordoba_(nio)' },
    { key: 'nigerian_naira_(ngn)' },
    { key: 'north_korean_won_(kpw)' },
    { key: 'norwegian_krone_(nok)' },
    { key: 'omani_rial_(omr)' },
    { key: 'omisego_(omg)' },
    { key: 'pakistani_rupee_(pkr)' },
    { key: 'palladium_(xpd)' },
    { key: 'panamanian_balboa_(pab)' },
    { key: 'papua_new_guinean_kina_(pgk)' },
    { key: 'paraguayan_guarani_(pyg)' },
    { key: 'pence_sterling_british_penny_(gbx)' },
    { key: 'peruvian_nuevo_sol_(pen)' },
    { key: 'philippine_peso_(php)' },
    { key: 'platinum_(xpt)' },
    { key: 'polish_z_oty_(pln)' },
    { key: 'pound_sterling_(gbp)' },
    { key: 'qatari_riyal_(qar)' },
    { key: 'qtum_(qtum)' },
    { key: 'ripple_(xrp)' },
    { key: 'romanian_new_leu_(ron)' },
    { key: 'russian_rouble_(rub)' },
    { key: 'rwandan_franc_(rwf)' },
    { key: 'saint_helena_pound_(shp)' },
    { key: 'samoan_tala_(wst)' },
    { key: 'sao_tome_and_principe_dobra_(std)' },
    { key: 'saudi_riyal_(sar)' },
    { key: 'serbian_dinar_(rsd)' },
    { key: 'seychelles_rupee_(scr)' },
    { key: 'sierra_leonean_leone_(sll)' },
    { key: 'silver_(xag)' },
    { key: 'singapore_dollar_(sgd)' },
    { key: 'solomon_islands_dollar_(sbd)' },
    { key: 'somali_shilling_(sos)' },
    { key: 'south_african_rand_(zar)' },
    { key: 'south_korean_won_(krw)' },
    { key: 'south_sudanese_pound_(ssp)' },
    { key: 'special_drawing_rights_(xdr)' },
    { key: 'sri_lankan_rupee_(lkr)' },
    { key: 'stellar_lumen_(xlm)' },
    { key: 'sudanese_pound_(sdg)' },
    { key: 'surinamese_dollar_(srd)' },
    { key: 'swazi_lilangeni_(szl)' },
    { key: 'swedish_krona_kronor_(sek)' },
    { key: 'swiss_franc_(chf)' },
    { key: 'syrian_pound_(syp)' },
    { key: 'tajikistani_somoni_(tjs)' },
    { key: 'tanzanian_shilling_(tzs)' },
    { key: 'tehterus_(usdt)' },
    { key: 'thai_baht_(thb)' },
    { key: 'tongan_paanga_(top)' },
    { key: 'trinidad_and_tobago_dollar_(ttd)' },
    { key: 'tunisian_dinar_(tnd)' },
    { key: 'turkish_lira_(try)' },
    { key: 'turkmenistani_manat_(tmt)' },
    { key: 'ugandan_shilling_(ugx)' },
    { key: 'uic_franc_(xfu)' },
    { key: 'ukrainian_hryvnia_(uah)' },
    { key: 'unidad_de_fomento_(clf)' },
    { key: 'unidad_de_valor_real_(cou)' },
    { key: 'united_arab_emirates_dirham_(aed)' },
    { key: 'united_states_dollar_(usd)' },
    { key: 'uruguayan_peso_(uyu)' },
    { key: 'uruguay_peso_en_unidades_indexadas_(uyi)' },
    { key: 'uzbekistan_som_(uzs)' },
    { key: 'vanuatu_vatu_(vuv)' },
    { key: 'venezuelan_bolivar_fuerte_(vef)' },
    { key: 'vietnamese_dong_(vnd)' },
    { key: 'wir_euro_(che)' },
    { key: 'wir_franc_(chw)' },
    { key: 'yemeni_rial_(yer)' },
    { key: 'zambian_kwacha_(zmw)' },
    { key: 'zcash_(zec)' },
  ],
  financial_account_status_ov: [
    { key: 'active' },
    { key: 'inactive' },
    { key: 'status' },
  ],
  financial_account_type_ov: [
    { key: 'credit_credit_card' },
    { key: 'depository_cash_management' },
    { key: 'depository_certificate_of_deposit_cd' },
    { key: 'depository_checking' },
    { key: 'depository_electronic_benefit_transfer_ebt' },
    { key: 'depository_health_savings_account_hsa' },
    { key: 'depository_money_market' },
    { key: 'depository_prepaid_debit_card' },
    { key: 'depository_savings' },
    { key: 'depository_bank_account' },
    { key: 'cryptocurrency_wallet' },
    { key: 'investment_401a' },
    { key: 'investment_401k' },
    { key: 'investment_403b' },
    { key: 'investment_457b' },
    { key: 'investment_529' },
    { key: 'investment_brokerage' },
    { key: 'investment_cash_individual_savings_account_isa' },
    { key: 'investment_education_savings_account' },
    { key: 'investment_fixed_annuity' },
    { key: 'investment_guaranteed_investment_certificate_gic' },
    { key: 'investment_health_reimbursement_arrangement' },
    { key: 'investment_health_savings_account_hsa' },
    { key: 'investment_individual_retirement_account_ira' },
    { key: 'investment_individual_savings_account_isa' },
    { key: 'investment_keogh' },
    { key: 'investment_life_income_fund_lif' },
    { key: 'investment_life_insurance' },
    { key: 'investment_locked_in_retirement_account_lira' },
    { key: 'investment_locked_in_retirement_income_fund_lrif' },
    { key: 'investment_locked_in_retirement_savings_plan_lrsp' },
    { key: 'investment_mutual_fund' },
    { key: 'investment_non_taxable_brokerage_account' },
    { key: 'investment_other_annuity' },
    { key: 'investment_other_insurance' },
    { key: 'investment_other' },
    { key: 'investment_pension' },
    { key: 'investment_prescribed_registered_retirement_income_fund_prif' },
    { key: 'investment_profit_sharing_plan' },
    { key: 'investment_qualifying_share_account_qshr' },
    { key: 'investment_registered_disability_savings_plan_rdsp' },
    { key: 'investment_registered_education_savings_plan_resp' },
    { key: 'investment_registered_retirement_income_fund_rrif' },
    { key: 'investment_registered_retirement_savings_plan_rrsp' },
    { key: 'investment_restricted_life_income_fund_rlif' },
    { key: 'investment_retirement' },
    { key: 'investment_roth_401k' },
    { key: 'investment_roth' },
    { key: 'investment_salary_reduction_simplified_employee_pension_plan_sarsep' },
    { key: 'investment_self_invested_personal_pension_sipp' },
    { key: 'investment_simple_individual_retirement_account_ira' },
    { key: 'investment_simplified_employee_pension_sep_individual_retirement_account_ira' },
    { key: 'investment_stock_plan' },
    { key: 'investment_tax_free_savings_account_tfsa' },
    { key: 'investment_thrift_savings_plan' },
    { key: 'investment_trust' },
    { key: 'investment_uniform_gift_to_minors_act_ugma' },
    { key: 'investment_uniform_transfers_to_minors_act_utma' },
    { key: 'investment_variable_annuity' },
    { key: 'loan_auto' },
    { key: 'loan_business' },
    { key: 'loan_commercial' },
    { key: 'loan_construction' },
    { key: 'loan_consumer' },
    { key: 'loan_home_equity' },
    { key: 'loan_line_of_credit' },
    { key: 'loan_loan' },
    { key: 'loan_mortgage' },
    { key: 'loan_other' },
    { key: 'loan_overdraft' },
    { key: 'loan_student' },
    { key: 'payroll' },
    { key: 'recurring' },
    { key: 'rewards' },
    { key: 'safe_deposit' },
  ],
  financial_asset_type_ov: [
    { key: 'airplane' },
    { key: 'boat' },
    { key: 'car' },
    { key: 'company' },
    { key: 'domain_name' },
    { key: 'real_estate' },
    { key: 'digital' },
    { key: 'other' },
  ],
};

export const up = async (next) => {
  // Create new vocabularies
  const context = executionContext('migration');
  const vocabularyKeys = Object.keys(newVocabularies);
  for (let i = 0; i < vocabularyKeys.length; i += 1) {
    const key = vocabularyKeys[i];
    const elements = newVocabularies[key];
    for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
      const element = elements[elementIndex];
      const data = {
        name: element.key,
        description: element.description,
        category: key,
        builtIn: false,
      };
      await addVocabulary(context, SYSTEM_USER, data);
    }
  }

  // Query for all existing Cryptocurrency-Wallet and Bank-Account Observables and migrate with a equivalent
  // new Financial-Account Observable
  const ENTITY_BANK_ACCOUNT = 'Bank-Account';
  const ENTITY_CRYPTOGRAPHIC_WALLET = 'Cryptocurrency-Wallet';
  const updateQuery = {
    script: {
      source:
        `
          if (ctx._source.entity_type == 'Cryptocurrency-Wallet') {
            ctx._source.entity_type = 'Financial-Account';
            ctx._source.account_type = 'cryptocurrency_wallet';
            ctx._source.account_number = ctx._source.value;
            ctx._source.standard_id = ctx._source.standard_id.replace('cryptocurrency-wallet', 'financial-account');
            ctx._source.account_status = 'active';
            ctx._source.currency_code = null;
            ctx._source.bic_number = "";
            ctx._source.iban_number = "";
            ctx._source.remove('value');
          } 
          if (ctx._source.entity_type == 'Bank-Account') { 
            ctx._source.entity_type = 'Financial-Account';
            ctx._source.account_type = 'depository_bank_account';
            ctx._source.account_number = ctx._source.value;
            ctx._source.standard_id = ctx._source.standard_id.replace('bank-account', 'financial-account');
            ctx._source.account_status = 'active';
            ctx._source.currency_code = null;
            ctx._source.bic_number = "";
            ctx._source.iban_number = "";
            ctx._source.remove('value');
          }
        `.trim()
    },
    query: {
      bool: {
        should: [
          { term: { 'entity_type.keyword': { value: ENTITY_CRYPTOGRAPHIC_WALLET } } },
          { term: { 'entity_type.keyword': { value: ENTITY_BANK_ACCOUNT } } },
        ]
      }
    }
  };
  // Run _update_by_query
  await elUpdateByQueryForMigration(
    '[MIGRATION] Migrating Cryptocurrency-Wallet and Bank-Account to Financial-Account Observables',
    [READ_INDEX_STIX_CYBER_OBSERVABLES],
    updateQuery
  );

  //
  // Migrating Cryptocurrency-Wallet and Bank-Account ---> Financial-Account in History Records
  //
  const updateQueryHistoryIndex = {
    script: {
      source:
          "if (ctx._source.context_data.entity_type == 'based-on') { ctx._source.context_data.message = ctx._source.context_data.message.replace('Cryptocurrency-Wallet', 'Financial-Account'); ctx._source.context_data.message = ctx._source.context_data.message.replace('Bank-Account', 'Financial-Account')} "
          + "if (ctx._source.context_data.entity_type == 'Cryptocurrency-Wallet') { ctx._source.context_data.entity_type = 'Financial-Account'; ctx._source.context_data.message = ctx._source.context_data.message.replace('Cryptocurrency-Wallet', 'Financial-Account')} "
          + "if (ctx._source.context_data.entity_type == 'Bank-Account') { ctx._source.context_data.entity_type = 'Financial-Account'; ctx._source.context_data.message = ctx._source.context_data.message.replace('Bank-Account', 'Financial-Account')} "
    },
    query: {
      bool: {
        should: [
          { query_string: {
            query: ENTITY_CRYPTOGRAPHIC_WALLET,
            default_operator: 'AND'
          } },
          { query_string: {
            query: ENTITY_BANK_ACCOUNT,
            default_operator: 'AND'
          } }
        ]
      }
    }
  };

  // Run _update_by_query
  await elUpdateByQueryForMigration(
    '[MIGRATION] Migrating Cryptocurrency-Wallet and Bank-Account to Financial-Account in History Records',
    [READ_INDEX_HISTORY],
    updateQueryHistoryIndex
  );

  //
  // Migrating Cryptocurrency-Wallet and Bank-Account ---> Financial-Account in opencti_stix_core_relationships records
  //
  const updateQuerySTIXCoreRelationshipsIndex = {
    script: {
      source:
        `
        if (ctx._source.fromType == 'Cryptocurrency-Wallet' || ctx._source.toType == 'Cryptocurrency-Wallet' ) { 
          if (ctx._source.fromType == 'Cryptocurrency-Wallet') {
              ctx._source.fromType = 'Financial-Account'; 
          } else
          {
            ctx._source.toType = 'Financial-Account';
          }
          for (int i = 0; i < ctx._source['connections'].length; ++i) {
            for (int x = 0; x < ctx._source['connections'][i]['types'].length; ++x) {
              if (ctx._source.connections[i].types[x] == 'Cryptocurrency-Wallet') {
                ctx._source.connections[i].types[x] = 'Financial-Account'
              }
            }
          }
        }
        if (ctx._source.fromType == 'Bank-Account') { 
          if (ctx._source.fromType == 'Bank-Account') {
              ctx._source.fromType = 'Financial-Account'; 
          } else
          {
            ctx._source.toType = 'Financial-Account';
          } 
          for (int i = 0; i < ctx._source['connections'].length; ++i) {
            for (int x = 0; x < ctx._source['connections'][i]['types'].length; ++x) {
              if (ctx._source.connections[i].types[x] == 'Bank-Account') {
                ctx._source.connections[i].types[x] = 'Financial-Account'
              }
            }
          }
        }
        `.trim()
    },
    query: {
      bool: {
        should: [
          { query_string: {
            query: ENTITY_CRYPTOGRAPHIC_WALLET,
            default_operator: 'AND'
          } },
          { query_string: {
            query: ENTITY_BANK_ACCOUNT,
            default_operator: 'AND'
          } }
        ]
      }
    }
  };

  // Run _update_by_query
  await elUpdateByQueryForMigration(
    '[MIGRATION] Migrating Cryptocurrency-Wallet and Bank-Account to Financial-Account in STIX Core Relationship Records',
    [READ_INDEX_STIX_CORE_RELATIONSHIPS],
    updateQuerySTIXCoreRelationshipsIndex
  );

  //
  // Migrating Cryptocurrency-Wallet and Bank-Account ---> Financial-Account in opencti_stix_meta_relationships records
  //
  const updateQuerySTIXMetaRelationshipsIndex = {
    script: {
      source:
        `
        if (ctx._source.fromType == 'Cryptocurrency-Wallet' || ctx._source.toType == 'Cryptocurrency-Wallet' ) { 
          if (ctx._source.fromType == 'Cryptocurrency-Wallet') {
              ctx._source.fromType = 'Financial-Account'; 
          } else
          {
            ctx._source.toType = 'Financial-Account';
          }
          for (int i = 0; i < ctx._source['connections'].length; ++i) {
            for (int x = 0; x < ctx._source['connections'][i]['types'].length; ++x) {
              if (ctx._source.connections[i].types[x] == 'Cryptocurrency-Wallet') {
                ctx._source.connections[i].types[x] = 'Financial-Account'
              }
            }
          }
        }
        if (ctx._source.fromType == 'Bank-Account') { 
          if (ctx._source.fromType == 'Bank-Account') {
              ctx._source.fromType = 'Financial-Account'; 
          } else
          {
            ctx._source.toType = 'Financial-Account';
          } 
          for (int i = 0; i < ctx._source['connections'].length; ++i) {
            for (int x = 0; x < ctx._source['connections'][i]['types'].length; ++x) {
              if (ctx._source.connections[i].types[x] == 'Bank-Account') {
                ctx._source.connections[i].types[x] = 'Financial-Account'
              }
            }
          }
        }
        `.trim()
    },
    query: {
      bool: {
        should: [
          { query_string: {
            query: ENTITY_CRYPTOGRAPHIC_WALLET,
            default_operator: 'AND'
          } },
          { query_string: {
            query: ENTITY_BANK_ACCOUNT,
            default_operator: 'AND'
          } }
        ]
      }
    }
  };

  // Run _update_by_query
  await elUpdateByQueryForMigration(
    '[MIGRATION] Migrating Cryptocurrency-Wallet and Bank-Account to Financial-Account in STIX META Relationship Records',
    [READ_INDEX_STIX_META_RELATIONSHIPS],
    updateQuerySTIXMetaRelationshipsIndex
  );

  next();
};

export const down = async (next) => {
  next();
};
