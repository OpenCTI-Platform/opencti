// noinspection CssInvalidPropertyValue

import { observableValue, prepareDate } from './format';
import type {
  BasicStoreCyberObservable,
  BasicStoreEntity,
  BasicStoreObject,
  BasicStoreRelation,
  StoreCyberObservable,
  StoreEntity,
  StoreRelation
} from '../types/store';
import { isStixDomainObject } from '../schema/stixDomainObject';
import { isStixRelationship } from '../schema/stixRelationship';
import { isStixCyberObservable } from '../schema/stixCyberObservable';

export const truncate = (str: string, limit: number) => {
  if (str === undefined || str === null || str.length <= limit) {
    return str;
  }
  const trimmedStr = str.substr(0, limit);
  if (!trimmedStr.includes(' ')) {
    return `${trimmedStr}...`;
  }
  return `${trimmedStr.substr(0, Math.min(trimmedStr.length, trimmedStr.lastIndexOf(' ')))}...`;
};

export const defaultValue = (element: BasicStoreObject) => {
  if (!element) return '';
  const entityType = element.entity_type;
  if (isStixDomainObject(entityType)) {
    const n: BasicStoreEntity = element as BasicStoreEntity;
    return `${n.x_mitre_id ? `[${n.x_mitre_id}] ` : ''}${
      n.name || n.pattern || n.attribute_abstract || n.opinion || n.value || n.definition
        || n.source_name || n.phase_name || 'Unknown'
    }`;
  }
  if (isStixRelationship(entityType)) {
    const n: BasicStoreRelation = element as BasicStoreRelation;
    return n.description;
  }
  if (isStixCyberObservable(entityType)) {
    const n: BasicStoreCyberObservable = element as BasicStoreCyberObservable;
    return observableValue(n);
  }
  return '';
};

const entityDescription = (element: StoreEntity | StoreCyberObservable) => {
  if (!element) return '-';
  const entityType = element.entity_type;
  if (isStixDomainObject(entityType)) {
    const n: BasicStoreEntity = element as BasicStoreEntity;
    return n.description;
  }
  if (isStixCyberObservable(entityType)) {
    const n: BasicStoreCyberObservable = element as BasicStoreCyberObservable;
    return n.x_opencti_description;
  }
  return '-';
};

export const resolveLink = (type: string) => {
  switch (type) {
    case 'Attack-Pattern':
      return '/dashboard/arsenal/attack_patterns';
    case 'Campaign':
      return '/dashboard/threats/campaigns';
    case 'Note':
      return '/dashboard/analysis/notes';
    case 'Observed-Data':
      return '/dashboard/events/observed_data';
    case 'Opinion':
      return '/dashboard/analysis/opinions';
    case 'Report':
      return '/dashboard/analysis/reports';
    case 'Course-Of-Action':
      return '/dashboard/arsenal/courses_of_action';
    case 'Individual':
      return '/dashboard/entities/individuals';
    case 'Organization':
      return '/dashboard/entities/organizations';
    case 'Sector':
      return '/dashboard/entities/sectors';
    case 'Indicator':
      return '/dashboard/observations/indicators';
    case 'Infrastructure':
      return '/dashboard/observations/infrastructures';
    case 'Intrusion-Set':
      return '/dashboard/threats/intrusion_sets';
    case 'City':
      return '/dashboard/entities/cities';
    case 'Country':
      return '/dashboard/entities/countries';
    case 'Region':
      return '/dashboard/entities/regions';
    case 'Position':
      return '/dashboard/entities/positions';
    case 'Malware':
      return '/dashboard/arsenal/malwares';
    case 'Threat-Actor':
      return '/dashboard/threats/threat_actors';
    case 'Tool':
      return '/dashboard/arsenal/tools';
    case 'Vulnerability':
      return '/dashboard/arsenal/vulnerabilities';
    case 'Incident':
      return '/dashboard/events/incidents';
    case 'Artifact':
      return '/dashboard/observations/artifacts';
    case 'Stix-Cyber-Observable':
    case 'Autonomous-System':
    case 'Directory':
    case 'Domain-Name':
    case 'Email-Addr':
    case 'Email-Message':
    case 'Email-Mime-Part-Type':
    case 'StixFile':
    case 'X509-Certificate':
    case 'IPv4-Addr':
    case 'IPv6-Addr':
    case 'Mac-Addr':
    case 'Mutex':
    case 'Network-Traffic':
    case 'Process':
    case 'Software':
    case 'Url':
    case 'User-Account':
    case 'Windows-Registry-Key':
    case 'Windows-Registry-Value-Type':
    case 'Cryptographic-Key':
    case 'Cryptocurrency-Wallet':
    case 'Hostname':
    case 'Text':
    case 'User-Agent':
      return '/dashboard/observations/observables';
    default:
      return null;
  }
};

export const header = (url: string, entitiesNames = []) => {
  return `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
    <html>
        <head>
            <meta content="en-us" http-equiv="Content-Language">
            <meta content="text/html; charset=utf-8" http-equiv="Content-Type">
            <title>Cyber Threat Intelligence Digest</title>
            <style type="text/css">
                * {
                    font-family: 'Arial';
                }
                body {
                    margin: 0;
                    padding: 0;
                    background-color: #f6f6f6;
                    background: #f6f6f6;
                }
                </style>
            </head>
        <body>
          <table align="center" bgcolor="#cccccc" cellpadding="0" cellspacing="0" style="width: 100%; background: #f6f6f6; background-color: #f6f6f6; margin:0; padding:0 20px;">
              <tr>
                  <td>
                      <table align="center" cellpadding="0" cellspacing="0" style="width: 620px; border-collapse:collapse; text-align:left; font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#444444; margin:0 auto;">
                          <tr>
                              <td valign="bottom" style="height:5px;margin:0;padding:20px 0 0 0;line-height:0;font-size:2px;"></td>
                          </tr>
                          <tr>
                              <td style=" width:620px;" valign="top">
                                  <table cellpadding="0" cellspacing="0" style="width:100%; border-collapse:collapse;font-family: Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#444444;" >
                                      <tr>
                                          <td bgcolor="#507bc8" style="width: 320px; padding:10px 0 10px 20px; background: #507bc8; background-color: #f507bc8; color:#ffffff;" valign="top">
                                              <a style="color:#ffffff; text-decoration:underline;" href="${url}">OpenCTI instance</a><span style="color:#ffffff;"> | </span><a style="color:#ffffff; text-decoration:underline;" href="https://www.notion.so/OpenCTI-Public-Knowledge-Base-d411e5e477734c59887dad3649f20518">Documentation</a>
                                          </td>
                                          <td bgcolor="#507bc8" style="width: 300px; padding:10px 20px 10px 20px; background: #507bc8; background-color:#507bc8; text-align:right; color:#ffffff;" valign="top">
                                              Automatic digest subscription
                                          </td>
                                      </tr>
                                      <tr>
                                          <td bgcolor="#ffffff" style="width: 320px; padding:20px 0 15px 20px; background: #ffffff; background-color:#ffffff;" valign="middle">
                                              <p style="padding:0; margin:0; line-height:160%; font-size:18px;">
                                                  <img src="data:image/png;base64,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VNX9//HXmdkGLN2Gih3rpdgXxNguYEEcCyYxRk00GmM0RhPb5pfvJnHtGo2aZjfRKCa6IBbYq2KDFRUErth7QQFR6sLuzpzfH2ewws6d2ZmF3Xk/H4/7zVc9d+69n3tm5s5nz/kck6huGA3cC3RFRL7tIuDyutqqVNZ7BmElUAcctB5cx6343sm6nSIiIiIiItKRxBQCkQLxvWXAewqEiIiIiIiISG6UuBIprMeBlQqDiIiIiIiISPaUuBJpXRwwbdh/HNCoMIqIiIiIiIhkT4krkda9X1dblcx5b99rBt5UGEVERERERESyp8SVSOua8vAadyqMIiIiIiIiItlT4kqk8J5VCERERERERESyp8SVSOG9AXymMIiIiIiIiIhkR4krkdbZNr+C7y0D3lcoRURERERERLKjxJXI2rUAS/L0WrcpnCIiIiIiIiLZUeJKpH1MVAhEREREREREsqPElUj7+Ax4U2EQERERERERiU6JK5H20QhMUBhEREREREREolPiSmTtlqW3tvO9ZmCGQioiIiIiIiISnRJXImu3PL3ly4fAIoVVREREREREJBolrkTWzqS3fPkQ+ERhFREREREREYmmJE+vk8IVn1YiTDoLA3wOtGRsGYQxwOB7yQwt5wFzgU0AG/E8LNAN6KJbIiIiIiIiIsUmX4mr9+pqq7ZJVDcocSWdia2rrYqSYNoSGABMbrWV760AxqYTXdH4XoogvBio1u0QERERERGRYlOSzxerq61KKaRShMqAX5MpcbWa72X7PtH7SkRERERERIpSvkZIGYVSilgLMLyAr6/3l4iIiIiIiBQlTe2TrGlK6HcYoIQgPFChEBEREREREckfJSAkK4nqhh2BnyeqGzQK6JviwH4Kg4iIiIiIiEj+KHElkSWqG36Kq+N0I/AXReQ776XtCMK4QiEiIiIiIiKSvx/bImu0elRVorph00R1w8PATUD/9H/+SaK6QVPjnC1wI662AnopHCIiIiIiIiL5ocSVtCpR3fBD4CPgkG/1l27ASYoQ8FXx9M3Tm4iIiIiIiIjkgRJXskaJ6obtgOuAu1tptlGiuqGbovWlLfhqRJqIiIiIiIiItJESV/IdieqG/YCHgDMzNI2rD33HENW5EhEREREREckPJR3kGxLVDb8C6oDtIzRfBTQrat9wLG4apYiIiIiIiIi0UYlCIADpKX9/BM7JYrd5dbVVKxW9bxgIVAJLFAoRERERERGRttGIKyFR3TAA+AfZJa1WAX9X9ADo+q1/PkQhEREREREREWk7Ja6KXKK6YS/c1MAfATbqfsZyR11t1YuKIAB9v/XPIxUSERERERERkbZT4qqIJaobhgH3Azun/5WJsl8yxooFfUp+rwh+6dtx240gLFVYRERERERERNpGNa6KVKK6YVsgALpks188BY/t3a18aTcTEoT1wFXAW8AKfE+F2p3tgN7AfIVCREREREREJHdKXBWhRHVDFfB0tve/JW54dkgFS7uZOJYNgB+mt4+A/xKE04G3gbfxvWJP2vjA3eptIiIiIiIiIrlT4qrIJKobxgA3ZXvvYyl4bkgFC/rE11QJazPgV+n//xPgHYLwHWACvndvkYb6dJS4EhEREREREWkTJa6KSKK6YR/gFmCDbPYzFqbs2ZVFvWKQyth8k/Q2FDiKIPwnUA/cCUzH9z4pknDvqB4nIiIiIiIi0jZKXBWJRHXDpsDtZJm0iqXgyehJq2+rSG9Hp7dGgvD19HncATThamPZThjyrgThIfjeI+p9IiIiIiIiIrnRqoJFIFHd0Bc36mm7bPZLGXh2SAWf5Za0WpMuwGDgz8Ai4CHglwThwQThdgRheQcNcdka/l0FcIB6n4iIiIiIiEjuNOKqONwL7IyrTmWi7GCBmTtVML9vSb6SVmuyX3pbBnwAvE0QzgDq8L0ZHSi+m63h38WArQnCUq22KCIiIiIiIpIbJa46uUR1w1+Bg9L/aKLuZwznfbB9+XQWJ88H9gA2LOBpVgI7pbeDgbMJwsXA9cB44D18b+V6HOaytfz7LXFTM+epJ4qIiIiIiIhkT4mrTixR3XAUcEoOu95ed3HVlVwMwJMEYQ9gW+BEIIFLxnQr0GnHge7p7fL09hFB+DiusPxMoHE9G8W0thpdm+NGYylxJSIiIiIiIpIDJa46qUR1wwbA74HSLHedBvw0Ud1g6mqrXELG95bgEkYzcaOh9gV+hEtmbY1L0BSyPtVmwI/T2zLgFoLwaeBd3GishevpbeiXjs8L6pEiIiIiIiIi2VPiqvO6FVcIPRsvA9//MmG1Nr73NPA0QVgJbAEMAAYCRwK7Ffi6KoFfpbcPcXWx3gGmAHeth/WkBhOED+B7LeqSIiIiIiIiItlR4qoTSlQ3/AI4PMvdmoBf19VWfRB5D99bBswF5hKEE3GrBfYHfoibVrgp2Y/4ysbm6e17wA+AawnCBuBq4Hl874t2Cnm8tdsBXAEsUc8UERERERERyY4SV51MorqhJ/CHHHa9qK62qj7nA/teElgOvAr8H/B/BOFWgA8cC+wJdGXthczbqjy9jUpvywnCF4CHgLtwiaPl+J4twLG3auW/7QJ0QYkrERERERERkawpcdX5XAn0jdrYWLCGCXW1VVfn/Ux8713gZuBmgrAL8FNgP1xtrG2AXgWMQ7f0sfbDjXiaDtxJEL4CvAnMz+NKhZlGlQ0BJqlrioiIiIiIiGRHiatOJFHdcAAwFjBR2hsLzaVmwdhJS0+oK/TJ+V4jcCNwI0G4Ga4u1nbAUFzR9dICn8Fe6W0F8AbwDkE4G3gQ32tr8fRMo7hGocSViIiIiIiISNaUuOokEtUNZcBxZDGKyRqYsXNFn4nf6/Y2NrwH+AvwZnraX+H43kfARwThk8C/gN8AuwK/BfbFjZYqlK64ovWDcXXAziEIFwN3AtcBC3O4/lSG/76HeqiIiIiIiIhI9pS46jw2B07OZodP+8SZ3ysex9IH+EV6+5AgfAq4F3gWVxdqZUHO2NWbWpXeHgceJwi7AXsDo4HDgM0oXCIrjlulsBK4ML29RRA+kb7+6cAqfG9VhNi3pj9BWIbvNambioiIiIiIiESnxFXn8VciThEEN7ftnc1LaSnl2+OFNseN3Dou/V8eIAjrgFeA9/C9hQW9Ct9bzuoklhsNtStwCrATrjbWJhSuwDvpY2ybPmYjcC9B+OjXrn/xGvbpkeE1N063WahuKiIiIiIiIhKdEledQKK6YRiujlK0m560vNm/jE82KoHWJ8XFgKPT2zzcaKTXgBeACfjexwW/ON+bCZyRHom1XXobmL7eqgIfvQtwUnp7H3gzff3PA3X43ufpdskIr9MbJa5EREREREREsqLEVedwQTaNW2KG2QPKM1dm+qZ+6W0fXDH1ywjCd4A/AQ9FmE7XNm4k1ixgVnoE2FW4el4nAOeQxUqKOdoivR2AWx3xGoLwdeBs3FTDTPbAFYUXERERERERkYiUuOrgEtUNWwD7RW0fT8GbW5SRKiHbxNVqBjdVrwwYAvwPSBGEzwCPAHXAx7jaWIUp8u5ed1l6uwS4hCAcAIwAjkyfVyVQUYCjG6A8ve0FTI2437bqrSIiIiIiIiLZUeKq4/s+bqW8SJIxeGezklyTVmsTA76X3i4FXgfuIgifB14GPm2HEVlv4EY0/TU9rTABHIVLGG0DdF/H92lHdVURERERERGR7Chx1YElqhu6A2Oi3sd4Ej7YpKRxWbdYF2xBT2174A+4GvBzcLWh5gJP4Xv1BQ+Mm1Z4Fy551h8YgKuLtWs6Xr3Xwe2qUo8VERERERERyU5MIejQhgJ7R22cjLOq7+LkcakY2wP3Ak0FPj8DDMKNfLoQqCMIFxCENxOE7TN1zvc+wPceB64HTgO2AoYDD5PvcWet667uKiIiIiIiIpIdjbjqoBLVDXFcwe/SLHabU95kp3OA9zHwAwCCcASuNtQoYGvctMN4AU45nn7trsDJwMkE4fvAROAJ4DFgJb7XWJCA+V4KWJXengUOIwjjwGhgJHAQsFn6/AqR0DXqtSIiIiIiIiLZUeKq41pdHDwqC8wF5n3j37qpe/XAeQThFsDPcKOkBuFW0SvkqLwtgF+ktyTwIEH4EDATeBPfW1zQCLoi7+PTGwThzsBJwGBgF2BT8pdwKiEIe+N7n6vrioiIiIiIiET9MS0dVQ9gnyzatwBhXW3V2qtb+d77wP8DIAgHAjsAHm5K4sgCX08cV1A9gUuuvU4QvgzMACbjex8UPKK+NxeXwCvHJa5WX/9BZDElsxVW3VZEREREREQkOiWuOq4uwAZZtG8E6iK39r05wByCsA4oAyqB/YArgS0LfG390tu+QDOwkiCcD9Tie3cUPLJuBcQZwAyCsAS3UmIlLqlWC/TJ8ZWVuBIRERERERHJghJXHdfJWbZfXldb9UbWR/G9FtxorRXAfcB9BOGWwOG42li74xI5XQpwjTHclMhyoCdwO0F4O25q40O42ljvAI3p88w/97rL0tvfgb8ThDviamONwk2p3IDMUypLcKsbvqCuKyIiIiIiIhKNElcd1/FZtn8yb0f2vfeAG4Ab0gXODwHGAtvjptZVFvjaVxeUB3gLl0xrAGYB7+F7hR3Z5HuvAq8CV6WnFb6Oq9fVmhjQLccjbq7uLiIiIiIiIsVIiasOKFHd0J3sp+v9ryAn4wqcTwQmEoQb4GpDecCeuKl+2xQ4HNsCF6T//xAICcIQmAY8VbCRWF9d/6p08ioTi1vRMBffU68XERERERGRYqTEVce0R7Y71NVW/bfgZ+V7C4EnCcKngZtxU/w2AH4PnNgOcfHSWwsuSdRIEE4G/ojvvVaQI7qVGCsitGwG3szxKD3U5UVERERERKQYKXHVMR0StaGx0FRm4LGXG7H2Nlx9qOeBRbjaUPmfVud7KVziaBWwBDgJOIkg/B7wQ9xqiFvi6mKVFqhfl+Cm5h0HHEcQfg7cBEzBFV5fgu815uFYW2XxPsp+9FcQ7oIrji8iIiIiIiJSdJS46ph2yKbxinID2Arg9PSWBB4HHiUI3ep5vrek4Gfte08BTxGEMVxNqARwAK7A+VYFPnpv4Lz01oKb2vgoMAeY2YYk1i4UJvm22p64kWsiIiIiIiIiRUeJq45po6gNYxZWlsfA4KosOXG+KnC+HHgxXRfqJVxdqNcKevZuRNa7wLXAtQThQGA7oArYC1cbK17gfp9Ib4uAmQThHODF9PW/n8Vr7U60EVFJfO+LHM51W71PRUREREREpFjpB3EHk6huKAe6R97BQnPrd7kbrvj3vkATsIIg/AJXo+pv+N7nBb8o35sDzCEIJ+LqRXXD1fG6GBhc4KP3AQ7CjfxqApYThJ8B1wE343tNa93TFWXvX+Dz2xi3IqGIiIiIiIhI0VHiquPpjku2RJaMlvYwuClp5bhpdbVALUE4HbgTaMAVF29sNZnTFr7XjCtivpSvVircEFfY/WBgALAhrjZWvsVwSbMKoC9wI3AjQRgA9+Dqgr0NrEqfJ8Dm6S2KuVmfURD2wE2hNOr2IiIiIiIiUoyUuOp4SrO5bwZLY0Xs69MEs7VXerPAe8AkgvApXF2oVwp+tb63ALgKuIog7AkMA44AdsSNyupW6DNIb6tXBXyEIJyKm1a5ObBpxNd5J4djbwpsrS4vIiIiIiIixUqJq46njCxXmTP5WTfQ4Eb/nJbe3iQIZwMzgadxiazCFnj3vcXAI7jkUQ9gN2AIsHd6K2SSpxTYKb2dA7yCWzEx6rTNZ3M45lbANuryIiIiIiIiUqyUuOp4erJ+1DzaLr2NAVYCXxCEbwAX43uPF/zoLkk2JT36qwyoxBWt/zFwQTtc/05Ztm/IqnUQGtzqkapvJSIiIiIiIkVLiauOZ1OyWnHPAKxK/0N5gfpQZXrbHDiAIEzhirvfhZsitwhXGyuV96O711yZ3hYCFwIXEoTDgNNxo7I2w9XFKltH98ymzy0bXYGj1N1FRERERESkmClx1fEks2och80WtNz6yoDyqbTY0cDOwMACn2MMODW9LcZNJ5xIEM4BpuN7XxQ8Sr43FZhKEJYC2+NWThwFeMC27XzPPgCyXZ2xd/qcRURERERERIqWElednAW6L0tZ9t/l38C/CcItcYmrPXFFx3fBTT8slJ7A/umtBZhOEL4ITANexPdeL2gA3AqAL6e3vxGEO+Om4O0NHAQMxtWvKqTX8L2VWe4zVL1XREREREREip0SV0XAGnp9+Q++9x7wHkH4CG61vl64WlW/BQ5ph/42DJeU+RmwnCCcD/wHuBHfW1TwYPjeXGAuQfggcCluZNMg4DxgnwId9Ykc9jlePVdERERERESKnRJXxWGD7/wb30sCS9PbB8ATBGEMOA74Oa5e1YZABfkvEG7Sr1sB9AX+CPyRIHwdl0x6AfgIWI7vNRUkIr7XgpvGuBh4F5hAEJYDZ+FqS/UH+qTP0bTxaBOzah2EvXCj4URERERERESKmhJXHU8uSaSNIrVyhc5XTyncEFcPagSwa3rbuMDXtj1wG9CMK+o+hSB8BngJ35tT8Mj63irgSuBKgrAfrrD7SNx0yt3hayPXovsAlxjLxlhccXYRERERERGRoqbEVcezCMh2db7sE06+twA3xe2JdIHzXXGJnP1w9aG2LuA1ri6ovj2uwPu7BOEM4EXgMWAuvre0oFH2vXnAQ8BDBGHX9LXvDpwDbJHFK90JNGZ59HPUzUVERERERESUuOqIFpLlyoJAvzYd0RU4n44rrH470B2XvNkX+B1uul8hbZXexgAXAp8ShG8A/8T3Hih4xH1vBfAMQbgMVwsrqiTwXHpaYjRBeBiwpbq5iIiIiIiIiBJXHZHNZadEdcNGdbVV89t8dLc63kpgAW4E1LUE4fZANa7o+ga4aW7lBeqvleltW+BggtACtwM3AvOAL4BV6Rpe+ROEJcD3gU2z2OtVYG6WRzoK6KJuLiIiIiIiIqLEVUe0EmjJdidj2Rf4X0HOyPdeB04EIAgHAXsBB+Cm+u1R4HgY4CfpbT4umfYMQTgbaMD3FubpONsC52a5zytkU9/K1dXy1MVFREREREREHCWuOp5VwAqynJ7XVGZ8CpW4+jrfmw3MBm5OJ2J2xSWyDgd2pLBFxzcCDklvAM8RhCHwMC6J9XEbXnscrvZW5JADT2Y58mu3dLxEREREREREBCWuOqIVwGKgfzY7JeOcyLS5e7E89RxwNb73VsHP1BU4n0cQTgKuwSWWPNyqece1Q6z2Tm/HAY0E4VvAZODarEZiBeFVwKAsj92I792QxTG6AmeTXXJMREREREREpFNT4qqDqautWpWobsh6Rb2SFrqwPLUbblTP6QThClxh9QeBz4AV+N6qgpy0G3W0JL29CdQBPyIIfwT8HNgO6AmUAfECnEGX9NYH2BOoJggX4Aq91+MSgSvXeP1BOAT4RQ7H/EOW7bcFfPVwERERERERka8ocdUxZZ24Mha6r0ixtFtsdXn3rrhRUNcAITCDIJyCKyj+QnolwcLyvbuAuwjCTXC1sIYCg3HJtX4FPvqGwM24aMwEXiQInwZCfG8mAEG4EXA32RdLXwJcn+U+/1C3FhEREREREfkmJa46pnnZ7mCspfeSFEsrY2tal9BLbyfgRl+9QBDOAh4A5uJ7Swp6Nb73CTARmEgQluKm5e0CHAwcCGxcwKMbXKJsN+BnwEcE4QxcMmsbYKccXvNv+F70AvpBOBCXtBNZ9x6Y3ofKiiFgdk73//7AJhizCdhuWNMFY8txi0SsxJpGsAsxfII187D2daydS0vLyzw/4TVqaqyCKiIiIvlw6LlTtygpSw2G2M4xY3awsJkxbGItG2HoYjAV1tpSAyutoRFLo4HlYOZZYz/E8qGxvGdTdtaK5LJZ9VeNXKGoiqz/lLjqmGawehW/iIyFritTUZr2BUYBI4AzgIUE4UvAeOBfWSVkcuFGer2IGwF1L9ADtzrhPsCpuCl1hbRZejs0x/2/AP6c5T43q0vLOvPgg12o2HIENnYIxu4L7IwxZi2fJC7V6/5PGVCGoQeYjYFdMIAx7r/Hy2D40YuoP3oqlsdpWTWeQ/d4WwFvZ5PnXEzMVK9fJ2Wb+Crp2YgxC8F+BHyMtR9izVxIvcTIwe/qBhZTv1gHUvZCRg68TPf+O+/RN/h43hBOKKIf9BOf7kVF789bD4t9jxEDt9IHSPsafe6UvvGy0sNNzIzAmn0xpj/Evv5k4v73a08u6ceYrga68tW/38Gsfo4xYGKGrvHuqSMuangNUlOxPLI8tbw+uHzEEkU9O2MumDokFo/NVCTa+nhkX6u7ZOiOxXbZR1RPu8pgzm09NqkLlbjqmGZlu4OxULkihUmCNZF2iQHd0tuWwBHArQRhPfB74G1gOa42VLIgV+lqTi1Ib88CVxCEGwOX4RJL5bhpfGUFOHqutbZ+je99Grl1EI4h+8LvIm0zdlyMU3YcScz8FGMOBbp9LSGVR6YPhtEYRlNWcQ1BOAeb+jdNK+/gsL0+1Y0oVubrSU+ArcDs8eUvD5P+CA7CxVj7PNZOhtRkptbN1gg+kXZ5jw6gX79LcIvGiLT/Y8qvx1U0VWx+DMb8BGP2M6ufy/P8mGKMiQE7QWwnDCd3i1U2J6qnPYM1d7QsXDBu4j8Pb9TdEFk/KHHVMT2V9Qezha6NlpKUpTnepk/9EeltKfAk8Hx6WuEsfO/dgl+5Swr9BIAg3A0Ylt62AYbgklnrymzgicitg7B7+qGwQl1a2sW4Kd3o3ffnwC8xZqt1cAYDMbHLKet6MfVz6kjZyxg1aIZujKxFT4zxMcaH2BUMP3oe9UfdjbW3MXLwywqPSEGdxeQ59zNy4FMKhbSXQ387ZePSsrJzm4mdYqB3ex/fYEqBAzAcULLBBtcmLmz4V7Nt/vNDl+37ju6OyLoVUwg6nrraKosrAB6ZNdB1laXryrz9sbo7MBq3el4dMIEg/A9B+HOCsH2+aHxvBr53A753HDAGOAy3UuJcoLmdb0sKuA/fey+LffYD9lWPloIbN62CyXMuoHffdzHmqnWUtPr6k2EpxowlHnuR+jkP8/BLQ3STJELH6YeJnUssHlI/5znq54ylpsYoLiKFeLsZg+FW7pzcVcGQQht97pS+iYum/bm0rOIdQ+y3rIOk1RreA72IcWZJvOS1Iy5q+OuY857ppzslsu4ocdVxTcl2h26NKSpX2fzPBnIGAj8ArgPeIQifIgivThceLzzfm4/vPQZcClThikqfANzTTvfjFXzv4sitg7AbcAMa9SiFNmnWUfSufIWYuRRjNlgPfxwdQln8Rern3MSEho10wyRiv9kLY8Yx/OjZ1M8Zq4CIFOR9ti2b9LtcgZBC2X//mniietoZ8fKK1zHmbJP9St6FfxtgSo3hdFNa8tYRF067cP/9a+K6cyLtT4mrjus/WX/wpiy9FyWTxtIIJAt0XmVAT9xIonOA2QRhC0F4IUG4GUFYSRCWEYSFSZ/5XgrfW4rvvYXv/Qvf+yG+Z4CxuDpZXwArC3D9+2TZ/pe42mEihTGhYSMmzxlPPP6/dT7CKvOnUwxjTqFLt7lMnvV93TzJou94GDOO+jmPMXnmdoqHSN5/tZ/BpJf2VyAk3xIXPj2g57BRz4C5wRj6rP9vBbqYmLmk57BR0w4//5mddQdF2pcSVx3X89nu0FJi2PbDpk8qm+1PgMtxKwW2xypfceAS4EPgadyorJ8ShEMJwvb5y4rv/RffG45blfAk4GpgMvmZUnguvrc4cusg3BQ3MkykMCbPGk3XypCYGZP317Z2JdYuxNqlYFN5fW1j+hKL30P9nP/w8HPddSMli75zIKZkDsHs3ygYInl9bxniJbcybko3BUPyZcyFz56CKXnJGFOVl0cTWIC1L2Ptc1gCLA9abL219hkLM7B8bPP0R2tjzJ7xkpIZYy6a+mPdSZH2o2lKHdcKYDFudFP0D1vLZkc+unT6ndcNu5cgLAUG4KbVjQAOBzYt8HkPSW8Ai4CXCMLXgNvwvecLHjXfWwTcC9xLENakr7stHsZN+cvGbRRqwqYUt5oaw7Cjf4fhD23sYx+AfcI9BJrXSSVfZ0nLh8yduJyamm8++N05uSt9NupFWXw7SA2A2AAMQzFUpVePy+Wp8AeUdR3MpBeOZNQer+nGFpp9BXi9/Q735aq1lRjTA2s3x5jKPPyaqABzJfVzqlix+CSOGL5M97YD9Yt1comp13WfI9ma3n2vAM5QKKQtxo4dV9o0YPO/GBP7eRu+Qz4G+1gK+4Q1qbmppH3tocv2/SLTbvvvXxOv3NvftCQWGwQMwZg9gAMxpkcOZ1EeM7E7j7ho2s7jL5l0ERT3irdJkouNNePXr7MyQ42h1RIU1toGYP1Z5dryoT4l1k6Jq45rGfAybkW9rCypjI0C/o7vNeMKmc8lCB8ELgR2xhUNTwB7Fvga+gAHprcfE4SLgGnAg8D9+F5hlqANwjhwF9DWKUlvA+fhe01ZHPs3wEHqvpJ3f3m4jJ36/xtjcqv3Y+10sHfSQj2HDIr+Y+6EkStwifSP+fqKpw8+2IXy/sOJxQ7HmuMwpm+WDxw7ES+fzuRZCUYOfkI3uIBS9m5GDrp4nZ7DA9P7UFG6DSUlu2PYHWu+h2GH3J5VzdF07bkTj750KAcPeU83uAP3C1mfnE797P8xYtDjCoXk4pAzH+7e3KP3eIM5IPtHFOZjUnfQYu4cf/nQMJfjT5lSk2RKzQfAB8BDALuf+o+SzXoPHErcHGMwx2c7ZdEYc0HiolFbfzGVH02ZUpMs1nubXnUxsT6dU6J62qNgRrV+A6kdXzt0ot6dHYMSVx1XEzkmrgCXuPo6l3xpwtWBeha4hCCsBM7E/YWtO65gYmmBrqcyvW3B6oRSED4HVAMzgUagCd9r25dCEG4ETKft9aWagRvwvZezOPZciU5QAAAgAElEQVQuwOm4qZMi+XPn5K706/cAxozM7kmQRuAmmlM3ceigMK/ndPjhjUA9UM9fHv4NO2yaIB4/E8zwLB4JexCLPUL9rB8yYvADutGd2JF7LcKNwn3hy383eeZ2UDKGGKeA2Smr1zNmZ+LxJ5k8a39GDn5XARZpI2MMllsY/8xAjWaUrJMIFwZ9rOn2KJis/ihuLa+QStaUvfXRA/fdd2zeVwx/8Z+ntbzoypg8vf9Jt5/Xs9/2Y4nFqg3smMV74/u9ho1qGrvhzifdd9+xKd1tkcJQjauOqxnI9YfmqER1Q+akpe8tw/cuxfc2B4YDvwXuBKbiipwX2t5AALwH/Av4LUE4miAckNOrBeGRwIvkpyj6Tfjen7M4tknHbxt1XcmrcdMq2HTTh7NMWiWx9maalw9ghPervCetvu2sQ5sYNWQc/sB9sfYwsC9l8WupHBO/j/pZR+pmF5mRu77JyIHX4A/cmZTdD0t9lj+0tyQWe5LJs7ZSMEXywJit6NLrSgVCsuGfX98DUxkYEz1pZbHzsKlTF099dOD4y/YZV4ik1bdNuf2kVeMvHfbvxc8+6qVS9kSwn2bx3vhx04D+f9fdFikcJa46qLraqhTwJtCSw+5dgOyG6freHHzvOnzvRGAMrh7WmbjRS4VWCRyNK2j+X2ACQTiOIPwVQRhtSG8Q3gTcDWyeh/O5C9/Lts7DGcCJ6rmSVzU1cfpU3oOb3hvxadDOJJUczIiBP+PQvT9q93MeMfBhnvnfbiRTv8BNMYwijondw+SXRuimF6mRA59ihDeSVPJArI0+0hWzBbHYg4x/plJBFMkDY09j0hxfgZAo9j/p9vLKePfxGHbN4jnl3pZky851lwy7aV1Mv5sypSY54dKhd5JavjPYOyO/NYz5WaJ66q9010UKQ4mrju1d3GikXFyS81F97zN87xl87wZcvabNgeNxRc9XFviay3HDd8cCVwLvEoSPEYS/Jwj3+k7rINydIHwVOAWoyMPxA1zCLos9wq2Aa9pwzBZ1dVmjYcfcAOaIiE+CKUhdxuev7M3IwS+v0/OuqbGMGvQ3VrUMwdrnIj4SlmHi9zN51i668UVs5OAn+Oiz3bH2yuirWhqPrj1vp6ZGi2KItJUxhji3aOVXiaLXZtvfimH/iM8py1Mpe2LdJUN/EKXYeqHVXeovqqsdemLKpn5qrY1Wz9bGrkpc8Mx+uvMi+afEVQdWV1s1F3gpx90HJKob2j76yE0n/Ajfuwvf+wG+1wXYHVf0cAkukVWo+d6luNpbBwJ/AJ4jCFcQhH8kCPsThKfg6qXskKfjTQWOw/c+z3K/8eReG+x54Gr1dvmOybNOJkbUVXmWk0yOwR90IccWfrh9ZIcNeYO3pw7H2jsi/mCqxMTG8+i03uoAReyk/VcxYuB5pDiaqKP2jDmaYUeeqeCJ5IPZgrKuejaRVh1x0bSzIXZclLYWFgAHTLh06J3r23VMuGTYbbFk8kCLXZz5rUEJ8fi9o8+d0lc9QCS/lLjq+F4BchlGWwEcXJAz8r0Z+N5o3KqBJwLXAg/jpjYWWhfg/wHvAzflOc5n4XsLIu8RhHGC8CpgYI7H/Bz4Ca6emchXJs3ejVjsxoit59PScgCjhjy0Xl7Laae1MGLgSdiIo0CN2ZZ45R3qBMLIgXWkkgcAi6P1nVgtk57fXIETyQfzM+pnjVQcZE0Or35mb4OJVg/N2ndMqnmfutqhz6+v1/PA5cOfpcUeYi0RFiYwG5dUlF+jXiCSX0pcdXyPkNv0vDKT24qE0fleEt8bh++dCxyDq4s1GrgBmN+BYvw6MAbfezHL/Y4EzgJynZ5yTlarFkpxuH1KOTFzJ5jyCK3ns6plOAcPeX69v64RXjXWXhDt95I5nMlzTlVnEEYOnk5LcnR6hcxM/aaSWPn1CppIxkzCx9E+i+M3M+6FHoqXfN3YX4+riNv4HZjMq9dbaz9JNjUdWHfpvm+s79c1/vJh00jZhI00YMCckLjgWdXlFMkjJa46vlnAwhz2M00l5oCNx806jcfDfgU/S99rxPdexfceAs7F1anaB7gCt9Lf+uot4GB8L7vRYkG4PXAruU8R/BO+d7u6t3zHZn3/hDGZ6zxZuwzbdCiHDXmjw1zbiIGXk7LXRvv2Mtfw8AtapVPg4MHPYFMnRPvmiyV4dE6VgibS2vcH92Ht5Agt+9NbI0vkm5q69r8YY6KU6ViapPnQB6/a792Ocm3jLxv6GJaLIr2N4rEb9t+/Jq4eIZIfSlx1cHW1VcuBV3PZN55kK2v4Oyk+JghfJgh/QhD2Jgi7EoSF6xu+14TvfY7vTcX3zsf39gB6AWcDb+BqY7UAdh2H92Vc0uqdrPYKwh641RZzLVx6Hb73e/Vu+Y5JMwZhzDkRfnS0YJNHMWK3FzvcNU793znAuAgtu1Fafp06hQAwctB/sTba9Nk41QqYSAYrV50CdknGdsaczKTZBytgAnD4+c/sbKyJsLKetdiWYyde8r2ZHe0ax19SdYV1M15af2tgtu8xbOQJ6hUi+aHEVefwRC47lTen6De/BeMmsu2MGyH0GXA/cA5BOIYg3IEgLPxfC3xvMb53Hb63PbA38HvgLlxx8kXrIKbTgKNyGGnVFbe6Ys8cj3svvnc2QajVr2QNP7jL/gJkfj9a+3tGDqnvkNdYU2NZ/sXJYDOPFDNmNPWzD1fHEAA+X/YbrH03QsvDeOTFgQqYSGsZiD0+IJU6J1LbWOwm6qb0VNAkVhK/NtIUQexVdZcMf7SjXqdJrjwd7PLMP7TN/xs7dlypeoZIHj5fFIJO4e+57NRSYtjq42ZKWr75WQyMAq4E7gEeBCZ+uVJfe3BTCi/FFXY/Alcb62dAHUSoY9J2/8YlrV7Pai+X4LuG3IvePw2cnI6BVbeWb5g8+xgg8xLL1j7BTa9c3qGv9Yjhy2huOQ4bYWECE7uCGg3FF+DYoStJpc7N3GeMoaT0JAVMJIORg2/B2szJBcPmdOt7rQJW3MZcMG2UwWSs62RhRtOSL37Xka+17rL930ul7J8ifN9s3Txgi+PUO0TaTomrTqCutmoxbmRSVixQkrT0W9Cytp7QBRiAS8RcBLxMEM4gCP9AEO5V8JFYvpfC9+bhe1OBW4CngOUFDuc1wM/xvU+y2stNrTwNl2DLxXTAx/eWq0fLd9TUGIypifCm/pxVyeO579hUh7/mQ3Z9AWv/L0LLHRl21PHqJALAqMH3Ay9EePw5lpoajWwVySS18mdEWbnTmJOon3OoAlbEPypjJnOZC0tLqqXlx49cf2hTR7/exuZl14P9NEJTLSYjko/PGIWg0zgnl52sMWw6vyVK0ziuZtOuuGl8zwELCMK7CMJdCMJeBGF+h8IGoSEIywjCnwHLcEmlDQoUv1W4gujn5pg82gO4Mcf31Mv43t74XpO6sazRsCOPjVaQPVnD6CEfd5rr/uKVq6JNGYz9XqOu5Ksf2smrM/cZNmfoUcMVLJEMRu35IdhfR2pruImJT/dS0IrP4Rc942MirFZu+duDlw+f2xmuuf6qkStScHmE98Www89/Zmf1EpG2UeKq83gZWJn1830MNvmshbJV1k0SzE5v4DggxBWIv4IgPJ4g3Jsg3KRNVxOE2wAn4P5y/k+gawFj9yZwXs4F0YPwEFwiL+vwA48Dg9V9pfVP6tgFEVq9yjsNf+1U133ssc0k+W2Eh8Jt2Ofoo9RRBICpD9wHLIjwBOQrWCIR+ANvw6YeztzQbEpFLy2aUYyPKaYkyh/QP4dlNZ3qwpvn32QtyzLGJ15ysnqJSBs/ZxSCTmMVEVa4WJOSJGz7YTOUtGnWxMa4VQH/BYwHxhOEtxGE2c3rDsJ+BOHN6de4DSh0Ad1JwBH43l9yKogehKNxNbFy8QAwGt9LqvvK2nvo7H3BDMnYztpzOe20lk53/aMGjsfaxyP8YDpbnUUAqKlJYu34zF3G7KNgiUT9gd54KpYvInwWn8DkWaMVsOIx5oIp2xps5vquKXtp3aX+os507ROuOGIZpO7N+K7AHqmeItI2Slx1HiuBZ3LZsSUO273fhGkhl1FXa7IxsBdwEnALQbiIILyHIBxNEG62xj2CcDOC8BpgJq5AuZe3s1m7q4EEvueGLGdbED0Ih+BGg/XJ4di34HvH4HuN6rrS+qe0OTNjG2tnMmLgw502BikuzfxbiWE8OmtXdRhxfSZZF+EHdhX/+EeJgiUSwaF7f4RNRfsDQSz2Tx6d1ltBKw4mXn46q9coX7ulNK76Z6e8fmtvztzIbH3YRc/uot4i0oafRApB51BXW5UC5uBGXmXfESxs/VEzxPKeK6rATSn8Pm6FwrcJwlkE4ZkEYXeCcGuCcBzwDvBrXNKr0BqBA/G93+B7K3N6BZeAuwfol8PeF+J7p+Q0wkuKy4Mv9AWTyNjOcnWnjsOogQGW2RnbxWMnqtMIAM1Ln8XaTH+M6MYWQ7dRsEQiGjnoDqydGOGnfD/i3f+igHV+Y8eOi+HKhrT+mJKyt9Zdu//izhiDukvrn8OSsb5o3BqNRBRpAyWuOpeZwEu57GgsbLSwuTHWbD8r8DmWAYOAvwBLgLeBsUBpO8SnBTcFcUt874mcXyUIBwBTgB2y3HMFcAq+dxmQ/QgvKT5lZcdiMrw3LB/xxSvjOn0sjM281Loxx2kEjQAwet8vMLwaoV9trWCJZPMk03wqls8zv7c4nklzjlDAOreVAzY90GAy/BHX2hbb0olrn9VYazIndE3MjFCPEcmdEledSF1t1UJcQiWVy/4bfpFcuOW85l9j+AmublNnqr20CvgxMBbfW5DzqwThQcBDwHZZ7vk5cBC+d4t6qkQWNz/K2MambubYY5s7fSwWLfsP1i7N9DHGllUHqeOIe2+QeeUqYzTiSiQbR+w2D5K/ivgr4+88ML2PgtaZH1NKvp/xo9jy7EOX7ftOZ45DitRDEZrtATWabSGSIyWuOp9bgOU5ffkk6T/ktVUtHOTdDvwMNw3uKFzR9086cEzGA33xvXvwvdx/4AfhcOBuYECWe87EjfJqUPeUyB59YRNshKWlU6lxRRGPY4euBJO54HY8NkadR9I/l97N3F/YQnESydKIwf8iZSdkbGfMJlR2uUEB68wfsxyauR90/ucUu7L52YxhwPQ88rwDdlCnEcmNEledTF1t1RvArJw/eA2nJ6obuuF7K/G9BfjeA/jeobgRRnsD1wIf45Jj6/tUt3eAw/G9BL63vE2vFITbABOBjbLc83pgL3xvqXqnZKWk/BBMpmKnNuTgIXOLJiY2mXHlHow5XJ1H0j6I8KXXXWESyUFq1WlgM68QZ8wPqZ+lFdU6odEXPbUrhk1b/Yi1NmWb7X87eywmXr3/Zxb7eqZ2yZLSPdVzRHKjxFXn9Egb9t2XNU2D873l+N50fO/X+N5mwJG4OlX1uATRF7gaUuuDecBtwL743sQ2v1oQ7gm8DvTM8hx+g++dhe+1qEtK1iyHZf7hwLiiismrH00GMhV37c/kWVq5R4gwtRSs7apAieTg4D0+IcVZ0RrH/+YWG5HOpISSURkbGZ6bcMXwecUQDwMNmduYndVzRHKjxFXndN2XP31zk/lBxPfq8b2zgUOAKlxNrPWhKPI44Eh876f43kdtfrUgPBV4FIhnsVc9MAbfu1pdUXJSU2MwHJCxXSr5aFHF5axDm7D2qQiPj/upEwluQYwMT0GxbgqTSI5GDrwLm6qL8It+YyoqblTAOhdrzPAIzaYUSzxSKRtlBPy26jkiuVHiqhOqq61aDjwM5FoA8NhEdUPmh/kg7IKrgfUc8JN1fNkfAEcDx+F7z+XlFYPwbOAfQDaFRa8EjsH3XlBPlJztdcSOYFrvd9Yuo6FuRtHFxkRIXJnY99SJBGsy1zS0Vs9BIm3RtPLn2AgrUhu+z6TZRytgnUpVxo/YJE8W0Y/qVyM004IgIjnSsuEdSKK6wQDU1VZFGUn1S+DtHA9VCZwI/PU7/yUIy3FT5v6ESxSt66HfjcDvgevaVHj9m9cYB2qB87PYax7wS3zvfvVUabPS+D4RfgQ8S01Nsuhi05J6kpJYptgMUycSoFuE99EKhUmkDQ7b61PqZ58J5u6MbeOxv3H/s09x1D4LFLgO/pvkwqcHgGn1N4CFZPPyz6cWS0xStik0tuKt1r9y1vv6wCLrLSWu1vcvhuqGLkD/r74D+BCXrMlkATAbGJTjoWv5euIqCLcAPOB44IfrQWjexw0/rsH38rfEbhD2wBWgjzqCbBWupthP8b3P1WMlL4zZK2ObSFPmOqGGuhkMP2Z5hqREfx6Y3ocj91qkzlTEYqZLhFbLFSiRNhox6D8Ec44Bc1SGlhvSvceNwLEKWseWisUHZxquaixzH7n+0KJZnGjCZfu/xZrqBItIXihxtZ5KVDdsAlyAq9HxGG4q3Od1tVWNEV9idUIl18RV16MubDjt/iN6zGBZ6nRgN2AnoGwdh2YlLqn2EL43M6+vHIRbAzcBB0Xc4x3gHGACvpdSr5U8Gpi5iXmpKCNTU5MkOOYVYI9W23UrHww8oa5U1DbO/OvLKHElkg8rlp9Ol27fw5gNWv/qMmOZ9NKxjBoyTkHruIz7Y3YGdq4iJSL5osTVeiRR3VAJjAD+D+iFm6o2AWiqq63KakpQXW1Vc6K64WlcYqU0h9Mp+3ijkj/HlqSSqRiV60mI7sEl8z7Ie6IoCLdN/8jtH3GPCcCx+N4q9VzJq5oag2WXjBXqbKqIHwjtXDB7ZGg0ECWuipu1W2EyvpE+VqBE8mBM1XwmvXQG8ZJ7M7aNxW9kQsMUxlTNV+A6JmPNLhEq6SpxJSJ5o8TVOpSobigDugJHAD/CFTl8G6ipq62qy8MhXgReAvbMZedeS1Nduq9IsbhyndauXYkbcXYRvje7IEcIwhOAO6L8DAJeB07F955SD5aC2HNMf4zpnqHVcqY+8F7xJiSYm/GBOWY0XL/of1mZzKs3mdS7CpRInowaMo76OWMx5pgM780N6NLtr8AxCloH/Ro2ZptMX8MpoxFXIpI/Sly1s0R1QzmwNW7a3WHAyUAz8BTwk7raqv/l61h1tVWfJKobAmB3clhBsltjkr6Lk+sqcTUPt1rhH/C9wkyJCsJK4Le44u6ZfArcDvwO32tRT5aCKS3dKvMTI69SU1PEBT7t3MyLpsa0ck8xq6mJ46a4ty7JuwqWSB4tXfILevTcD9iw1XbGHM3kWT9g5OB7FLSOx1i7RaYRrTFr31CkRCRflLhqJ4nqhs1wBb/3BHbmq+J9fwYeAJ6rq61qKsChrwNOA/pk/dMQw4D3mnhvs1Lacemyj9IxmQLMKliSKAj7AHcDoyK0vhq4F997Xj1ZCv80mNoS4pnencX9YztpP8z47WXt1upMRWyvxECMyTTNPcmqpfphJZJPR+2zgMmzf0Esdl/m77vYDTw0/QkO2+tTBa7jGPGbyV0z1jIDmpqbP1G0RCRflLgqoER1g8GNdroi/b9dvxbzeuAEYGFdbVXBRvDU1VZ9mqhueBI4Mtt9UzHosTzFJvOTfLRJHApbfnwlrrbXP4ClBS12HoQHAhOBTCtOvQKcBMzQKCtpP2aLCI2K+2FwVfITSjIl90w/9aVifrqJH5yxjbUhRwxfpmCJ5NnIQf8lCMeRafVAY/pSVvH3XJ5RZd0pK+mSceELC8lu785foGiJSN4e7RSC/EpUN1QAOwDHAWNx0wJXa8aNrrq4rrZqRnudUyrG3bFUbg8Fybhhuw+a+GiTLoU4tSQwH7gRuB7fW1LQQARhF+A8oKa1cAHLgHOBW7VaoLQ7E2ElNGuLO3E1c8J8hh+dAtPKPGbbi3/8o4TTTlPSuTjfR2Mzv4/MNAVKpECams+grHR/YKPW36uxBJNmH8eoQXcraB1DjHjfzB/BduF99x2rZ2gRyRslrvIgUd1QCmyJG1V1KnDgt7++gQbg6rraqgntdmJBuCWwz4QSc/5hTyyjrNliTXYvkTLQd3GS7stSLO0Wc+XJ2245MBu4H/gzvpdsh1jshJvyd0grrT4A/gtU43uN6tmyTljTJ/OKghT3tIqamiTBMZ/RWg0VYwyb7Lkhrl6eFJNHXhyIMZnrW9nU0wqWSIEcuutCJs06nXg8c+3WuLmeR194nIP30NSyDiAWi1R+RNM/RSSvlLhqo0R1w4m4ZMhgYMc1NHkc+BvwWF1t1eftclJBeDButNdegIeF2QPK2WdWIyvLTPavZ2GXt5po2L0LNLUpc7UqHYtHgRfxvYXtFI+zgDP5qq7Yty0HaoEH8b1QvVrWsQgPhEZLiFsWYTIU/y01vVDiqvjEy38boQOtYnHTRAVLpIBGDb6f+jn3YMwPMnyn9SFW/g/cKtuynjOYnhk/YS0rFCkRySclrnKUqG74JfAnXJ2k8jU0WYVLltxeV1vV3C4nFYS7AjfjViysYPWyW0nLpxvEWdItRnlTDqOuYrDRZy1ULkmyrGssl1pXFrgsHa8WfK+94lEC3IFL4pWupdXNwO+Ahe0y8ksk8xNhj4xtYimNCHSfsa0rtV0VpiLz0EsDMPwg8xcbkzh2jyUKmEiBrVz1SyoqDsg4DT5mxlA/68eMGPwvBW19lyrLtIiMwaxUnEQkn5S4iihR3VAObAv8HDiFtRf2bgHuBH5XV1tV+L/0B2EFbmri+cD31tasJW54f5MSdnivmWQOg65iFrZ7r5mXdiqP/KgCvAvcBPwV32u/LzCXsNoTuB3Yfg0tlgHjgT/he6+pd8v6xWR+kyXtKsXJriTTnMpUiRJXxaYsfgNmrX+o+Fr3Sd6lYIm0g8P3+IzJc36OMQ9kbhy/jvEzAo7YTSNl12MpTFks46OMnlNEJL+UuMogUd3QAxgG/Ag4PkPz6cCFdbVVjxf8xIKwF3Ao8FtgSMYvGQOf9Sqh+aMWYqncpvv1XJqkS6OlsbzVH4ufAjOBW/C9/7b7DQvCTYGz03H5toXAFOACfO8t9W5ZL1nKMta4Iq4HwigjrmK2i8JUROrnnIQxIzO/x+y7vPvc/QqYSDsZObCOYM7dYI5rtZ2hN11L/wkcrqCtv4ylNEItTj2niEheKXG1Fonqhp7AL4CDgAOA1v648DHwB+CButqqwi79GoT9cSO+DsIl1CKPn/qsV4xlXQ09l2Y/XRCg17IU3ZenaCxf4/Dg6cA9uCL0DfiebfebFoQ/BH4D7Iabnrj6KhcD1wMP43taRUrW9yfC0swjiZIagh9lGkLKxBSnIjFpxiAwf43Y+mqtNinSzpY2nklllwMxZpPWP9rNaCbPPpGRg+5Q0NbTb18yf7dat5K6iEjeKHG1Bonqht/jEiBdIsTof8AZwPy62qrCJWuCMI6rEXUG0I1Mk8vXoKkixqcblNBjWVNunaXF0v+TZhb2iX+9zNUs3Ei0d4EV+N66Wfo2CO8CfsBXCcbVv/z/iEtafYHv6YeKrP+siWVOR8fUl41NZZG3l85s8qytiMUeZO1T+L/+Bnufle/eoqBFEIv9iSD8U8f/TE3+mBGD/60buo4dudci6mefBmZ85s/32LU8/FzAoXt/pMCJiAgocfWlRHVDX+Ao3OpyG0bYZQHwx7raqhsKemJBuBHwU6AaqGzTayUtb/QvZZsPmokns8+xJeOGbT5uZu425V80Vpj/Af/E96avs5vmalmNBv71tdgk0/fmAeASfO9D9W4RkU5q8qytMLEnwGwR7YuMszj8cC1uILIujBg0gfrw35gMpTcMvSjtehOuJIaIiIgSV4nqhk0BH7gU2DTiblOAE+pqqz4o2IkF4cbAMcAFwOZ5eU0LTeUx5m0Qp/8nLTlNF2yOGw6euvy+By6pOnWd3rggHAz8H3Dklz9H4GXgXuA6fG+53t4iIp3Yoy/tRyx+H9H+2ATWPsiogeMVOJF1KLn0LEoqDwLTr9V2xhzC5Fk/ZeTgWxU0EREpuvofieoGk/7fWKK64Xzc6nJ3EC1ptQQ4CxhVsKRVEG5OEP4BmAjcQL6SVqulLG9vVoqxuc9qtIbjExc1rJuix0G4AUF4Wfq+rU5a3Q2cCByC712ipJWISCf2l4fLmDy7hnhJQNSkFXzA0iUnK3gi69jBQz8nlYr2x89Y/BomPb+5giYiIkU34qqutsomqhtG4ZJVfbOIwUJgSF1tVeHm2wfhL4DLgYqC3RsLizYsobEiTsWqVE6jroAuGM4ArmrXmxeEBwO38FWScRxwPjAPaFonBeFFRKT9TJ41mlj8SmDHLL74VtGSPJqj9lmgAIqsB0YOnkj9nDsw5sQMLXsSr7gZOFhBExEpbkWTuEqPtNoeuOT/s3ff8VJU5x/HP2dvBSzYC/ZeFhDrgF0XECyMjRg1tmissUajjlGMDpZoTDTG3n7RJGJiBivC2gtjASlriRV7V0Tgcsvu+f0xS4IG2L07c6/svd/368UrEWbPnHmm3NnnnvMcolpWZb/xAncHvvPTDulYVKdpJ2AUsGOnBKPV8tLmDez2/Fya6ysubnwGnZG4iorS9wPOIiq+/gFwA3A5mfQ7uoVFRLq4++/vQcM6+2E4A2MGtPPTeQqFw9ljixcVSJElSPPMU2nsPRhMiRkPZigTph3N4H43K2giIt1Xt5gq6HrhKkSrBL5K+5JW3wEndWDSqj9RTaZHWVzSykR/avOWxlZLyv737ypi4etla/hshVpSla8BuLzrhUd06InL5tYD/gxMBNYFTgX6kkkfp6SViEgX9tDLKzJ+6k+YMP12Gtf5jJS5s7KkVf5QhvS/WwEVWcLsteNMLMeUta0xV3L/S2sqaCIi3VeXH3HleuEhwEmA086Pvgr8MvCdxxLvVDa3AXA8cAiwymK3TUF9s2WTGa0sPytPKm9pqTN8slIt769WS2uDgbb2d6EAM79aNvXm8t/mt6ayFFg9cKDrhX8NfKcl4fisSjQCbTPgNWAk8CSZ9Le6ZUVEqtyYMXUstb9WYP4AACAASURBVHYj89oaaejVm7qa1aCwGsZsACZNNMp2U4wxMfYyl3zhMIb2/6cCXiFrXwamVf1xFApv62QuoQb3fYjx024jlTpy8RuaZWhsvAUYoqCJiHRPXTpx5XrhfURL6da086NTgW0TT8gAZHNHENWxWpEyRryl8jBwWhPLzSpgFqjgtPy3eTZ4v5UpG9fz2Uq1UP7IKQscYmvNI2t+1rZ5IcU/gJUrPJr+xS8YLyUYnwuAY4ATiVZUnEsm3aJbVUSkg6RSF5HNXdTp+61f8D9qkmvX2rdoa9mPYVtN18mNFcd7GdLvYgVCOtTcr0+j14qDMSUWIzIMZvz0XzCk740KmohI99PlEleuF6aAXYB/ActU0MQdge8ckXjHsrm1AB84tPwvE7D2B60sNyvKSi1YSD1loUdzgV0mNfHu6vW8uXYdM5dOsYjq5HOIfmt6K5n0f2oE1HvhROAFYK8Kj6oPsJXrhZMC37EVxsUAdcAWwIHAG2TSWkFGRETaz9o7aJ55KnvtOFPBEKmGF/ddvuWRacdQk3q45LaGKxg35RH22OI9BU5EpHvpUjWuXC9cHriGqGZUJUmrC4GjEu1UNrc02dzPiaYeHtquzxrDSt/kvzfS6oea6wxrfdrKTpPmsuWr81h2dn7B+lefAX8FdiWTHrRg0gog8J024HagOcYRHkO0CmKllgd2BuYCZ5NJ36TbUro1g1bHFGk3+xptbbswuO8RSlqJVJmh/cZh7S1lvBcvTW3NLYwaZRQ0EZHupeoTV8XVAnG9cCAwFjihkjde4JjAd0YFvlNIrHPZ3JZEiaObgV4VfIGlNl/6O2xbDRgL63zcxg4vz6PvG82s+E3+72zQ4JBJH0ImvcjVlALf+ScQp/7DVkSJp0rNIpOeQCadI5PO65YUsaWr1plWvbSXM2I4ZQsKU5e/X16jUDiCt5/rxx5bPKl4iFSpb5pPJ1o5utQPwN0ZuN9xCpiISPdS9YmrwHes64U/JxpltUOFzfQHbkm0Y9ncacDTVD4ND6ylqTH1vSmCi5Ovgbo2y3oftbL9lKZh+9741Vn7nROWMx302phHe2nFn8ykW3Ubiix439NU+r29plGBKmOkZ8GqPl7XvEfasIWHsPn9eOafmzOk3x0ce2ybAiNSxUZuPQubP7q8by/mcsZPXUdB+3EUUqVHhhtsSpESkSRV9UPF9cJ61wt/QzSiqUcFTXwF7Bz4zvSKazT9UDa3ItncGOD3QM94Pxng0xVqKLRzbIWxYCzLWsPxhRQzXC/c3/XCxY34uot40wXTrhdurNtJJBHzyrjLGxSmMmJgUOKq65iDteOxhZNobV2Nwf32ZHD/fzFqlKbWinQVg/uPB1u6ZIQxS2FSt2rK4I/05bFAGb901nuKiCT87KnWjrteuCxRwuq3FTbxMXBA4DtPJdapbG4YMJGoyHh8Fj5ZqZYvlqulJm+p8KdzH+AfwETXCw92vbD+hxsEvvMtEKe2VA1wtG4nkSSY0okrk9KIKyj9UpzXiKuqZGnF2leBMdjCeeQLO/H1q8sxuO9QBve7luEDvlSQRLqolrlngH2/9M9Bsyvb73eCAvZjvKYUSv6y2xqUuBKRRFXlqoKuF25IVFR8UIVNfAbsG/jOC4l1KpsbBZzGgkXh5xdJj1ll5eXNG5n9rqHP5200NlsqzGD1Bf4CHOV64dWB79z3g3+/BDieytck/ylwpm4pkbhf2m0TxpR6aVTiCttY8mGYyn+nOJV1zb1MtPJsp+wNaMHYZqyZB8zD2K8p2E8g9Qmt+U+Y88YMRo7UNHKR7mj4dt/xyPSfU8OEktua1GU89NLDDN/6HQWu8xSMaS498sHoPUVEElV1iati0upxopFElZgDOIHvzEikQ9lcT+BZosTQf5M+dVA/19LQavlu2RrI28oSWBbm1cIrGzTw2Yq1p+0wuWmngmHfCnubAnYHBrpe+A5wUOA7rxT/7QvgOuCkCttexfXCswPfuVS3lUgMhtLJFmuW7/ZxsmbFkkn85rZvdEGVE0t7L0P6XaxAiMgSYWjfLBOm3YBJHVtiy17UN97KqFG7atpw50nZwmxMqtTPFSWuRCTZZ081ddb1ws2AB6k8aTUb2CfBpNV6wDPAFsxPWhnoNdey27NN7P/odwx/ejYH3T+LTd5poUdzu3+mWuBL4M6CoeHzA/v/4d5LnP2AnwBvAJX+RronkAZyrhde6HrhmkRptQlQRmHohasFdnO9UEODRWIlEcwnpZ/cZrVuHaOrH6rHsFzJ7ea9r8SViEg1mjvrV1hbzvv6zgza/yQFrBOZmq/K2GhFBUpEklQ1iati8e+HgQ1jNPPzwHceS6RD2dxQonpWA/77jIZlZhfYZdJclpuVZ25Diub6FPMaDOk3W9j1xbls8m4LjS22nAl5M4FrgIFk0j8jk24pxsEEvjOGKPF0LPByzCM5n2iKyHnAd8CrMdrqS5TEE5GKn8qFj0puY1m1W8do45VWLmOrbzXdTESkSo3YYTbYn2Nt6d/6psyljJu8voLWSVoKZSSuWEWBEpFEvyJVQyddL9wcCIC1YjRzQjHhE182dxRRwfP/+fK0zset1LVZ8jXfr77SVgsNLZbN32lmh5fnstE7LdS1Waj5n7kuTcAdwHAy6VPIpN9a8B/nr34Y+E5r4Du3AXsCpwDvxjii3sAo4FpghRjtrAr0c71Qq7yIVCpf+LjkNqabJ65SNWW8ENsPdDGJiFSxwf0ew3B9GVv2pKbuNq0y2DkK5svPS76mGBr3PPvp3oqWiCT2+r+kd9D1wrWAR4BNKvj4/N/SnB74znWJdCibuxD4E7DU/zykC9Bz3qILWVkD+ZRh6TmWzd5pYbcX5rLWhy0Ljr56HOgPHEsmPbGc7gS+80mxP9sCZwH5GEe3KbBOzAgdQTQVUUQqYU3pxBVmre4dpJrSx2/LWJVKRESWbHO+PYtyfjlrzI7ssN8pCljHu+/yEbOBklPx6wuFVRUtEUnKEp24cr1wOWAMlde0MsD1wNWxO5PN1ZHNHUs0ta7HonZWkwdjS30vjf63R7PFmT6PHV9sYuVv8reSSe9GJv0mmXRze7oW+E4h8J0vA9/5HdGop3FEReh/DIOANXRriVSqrJFCm3XvGJlNy/gS856uJRGRKjdih9nk244qa8qgTY3mwSkbKmid8arCjFKb5Gtr11OgRCQpS/qIqz8B28X4fAicF/hOPoG+nA+LH65cMDCnZ4pCOwYqt9QZVv4mz84vNR04wgvvdr1wpzidLCawhgG7AfcAzT/CebtCt5ZIpU+t4H2wsxa7jaE3D0xZvRv/6CqduCoUXtfFJCLSBQzd4gngzyW3M/SgoeY2DhyTUtA6li2rRElqM0VKRBJ7+1/SOjS/PpLrhRcCB8doajZwbOA7X8XuVDQ98LwyfmDy2XI1pOx/R1WVI5+C1lqWNjASuM/1wttdL9wkTpcD33mBaPXBfYDxnXwah7heqHntIpWIlvSeXnK7ejbvxlEqI3FlXtHFJCLSRXzz1a+xvFN6Q7M9x2x6qgLW0WzJxZxS3X50uIgkaYlLXAW+Y10vPJRohFMcQwLfmRa7Q9ncaOCc8p7h8Mkqtfx7nXp6NhUq3eOywOHARNcLb3O9cNk4sQx8ZzzgArsAkzrpNNYDw3V7iVT6PsjUMh7f3XMFzxtuqMWUkbjKz8vpQhIR6SJG7jIHa48sa8qgMRfzyEsbK2gdqFCYXsZWSlyJSGJq+W8B8zjqkuqQ64V9oKwVRBbnj4HvTIzdmWzuMMpNWv3nQQ6vblRPU4Nhs3daqG2zVLjESW+iQueHuF7oAhMD3/mmkoYC32kCnnS9cBvAB35OtHpgTQdeW8cDf9Utloj6BNqwCmNVKZ10T6V2Bn7X7SKz9nYDKLkAhP2YPbf9TJeRiEgXMqTvU0zIXQOcvNjtDD1INd7GgWN24J6RBQUueXljptaWevE0pt+wXz5U//A1w1u6Q0yGnfVEn4a6hltKvI1/F4weeKCuIJH2SwFfAnEf6n2S6IzrhT2AW4FeMZp5GjgjdmeyuWHADRV9tg3eXauOx7ftwb/Xqae11nwboyd1wIPAo64XHuN64VKVNlQcgXUu0QqEFwNvd+C1NcD1wnV1iyVihwTa+FhhrCJtbWWMjrQ7MmpUTbeLTapmx9Kh4TldRCIiXdAnH5+DtW+V3M4wkGM3OV0B6xgPXDL+DaydufhTQI/6pZbdtrvEpL6mrh+YoSX+rK+rR6TCrwDAO0Bb3IZcL1wx5udTRCOMhsT8cv7L2MXYs7nNiUYLNVbcRh7mNqZ4fYP68V8tm3KJCpbPi9GrAcCNQNb1whFxDi/wnfcC3xlVjPXVQNN/vu4lpydwkm6xRCSxQs6bCmMVufXNydhSS02bZdhuxIBuFxtjlbgSEemuDhsyl4I9CmzpX7pbcxEPTt5EQesIo6w1puTsFoPZufu8n6Q2Ln1J6n1cpFKpwHe+IIHEFbBvpR8sFmTvAVwUY/954LbAd6bGOopsbkOiYua9MUST6WqprBqY5SoK7B+evs0TRFMO08DdMeO8HfB31wufdb1wcJyGAt95h2h0Whq4Fiqd1biIn1XguF64gm6zWNfjisUrMK5JCmYVuWdkAexjJberqR3WreJyww21GFN65dVC4QldRCIiXdTQfk9T4OrSb6Kmkfq627vl6OTOYO0zJTdJdafEVen6m1a/SBap2Px0zJcJtLV1pR8MfMcClxHVXarUh4HvnBfrCLK5HsAfgdWNhaVnF9j0rRa2zDWzzoet1LdaTHljkpqAU8mkT2f39OziMbYFvvN24DsHATsSjQ5rrrCnjcAgYLzrhbe4Xriq64V1Fca+LfCddwLfOQnoS1RbZ15C19dm0K1XPkvCRiRTQ+49hbLaXgjLWA3U8JNuFZO1nd3BLF/iRfpTwn9N0QUkItKFNc84F2zpJIAx27H9/r9SwJJnDBPK2GyXPc9+ulusNG6iUiyL36ZQeF1Xjkhl5ieuHk6grb6VftD1wgxwIpVPVWsC9kzgGI4ChmJgww9aGBzOod8bzaz/QSvbTp/H4HAum7zbwjJzC1CzyMFJ/waGk0n/kWxuoRsFvvNM4Dt9iAqYP5lAn6cBF7teGGs4dOA7OWAb4BjgCeJPHewNpIvTQKUyWxC/OPs8Muk5CmW1KZSRuDKbM35q90kO16QOKLmNtQ8zapQWIxAR6cr23ruJ1sKRZU0ZNFzIuCla4S5hgf/IS2A/W3zoTV1dqm5EV4/FLic80ctiSn4Xzre1hrpyRCozP6GQTaCtZV0vrLQm1OX/eb5V+PnAd16J1ftsbmvgcgyppWcX6PtmM4WUobne0FoLLfWG+lbLZu82M2hKE5u83Uxt3v4wgTUFcMmknwAgk7aLf+A7txFNsTwSeCtG71cCziIagXWB64UV/2Yj8J2WwHfuBIYTJbDeiHld7EmcWmGyEfGnCj6qMFahIf1nYG3pqc+p1EHdIh433FALuKU3NPfp4hER6QaG9X8Wa/9Qxs+FBmpqNGUwcaMsmJKDH6yxXX4Vvd6967czpVZrt/bLB36381u6bkQqMz9x9VgCba1MlEBpF9cL9wfijBR6G7gmgf7fAfSkzrDJjBbsQnJo1kA+ZWhstmzybgu7P9/E+jNaoM6A4SFTYCcy6XYNAQ1855vAd24nql11LJQqyLxYawLnAznXC2NNmwx8p4lohcdtgDhDrIcDDbrVKpDN1QOrUVmFte+1pGBWKcsdZWxzNFc/VN/lY7HuQBdjViwRi5m8/sFDunBERLqJee+dh+XfJbczZhsG7X+WApbwa0ohP6aM95TBw898YpUuHQfDHqW3Kl3MXkQWLQUQ+M48YFbMthqBNdrzAdcLa4BfEBVmr9RZge98FTNBcBpRPaboQFpsWWO/ejQX2PL1ZnZ/Zg5HBd+evN9jsyutWUXgO18HvnNjMYbjiKY/2grPaR/gItcL33K9sH+lI+EC37GB78wKfOdK4N0YET5Mt1pFegArJtDOgwpltb6Qz7kLW2LxDGNWZbM1D+n6P63MKWW8Ov6Tk4e36MIREekm9t67iUJreVMGU4zqVtPrO8GHX+UmWPhi8a8ppr6uvv74Lv6SsnfJNxRbeFJXjEiMu2yB/x93SlgDUcHw9tgP2D3GPicU/1Qum3OAKxb8q3yKslNGrbWw7OwCXy9T81a+hv9zvTDWKl+B78wNfGcYsBfRKLDZMZpbn2j64l2uF+7hemGckU+3xPjsGbrVKrIi0YirOPLATIWySu3jfA62nBqEp3fpODwybUswO5Tcrq1wmy4aEZFuZuiAiRTM70tvaOoxNXcUp55LAibdeGybKfD3kpHHHLfLEbd3yRkY7jlPb2jKmD2Ub2sdqytGpHILJq7iDl+sA9Jl3+TRKKC9KTUfeNFagbsD3/mu4h5nc0sBv/1eHNos7/app7ZQ/mCnwn8//RNgjOuFY10v3CJOMAPfeQz4OZAhfo2i/YAHiBJYlfbr9hj7X9P1wg11u7XbasCqMdt4tXivSNWyN5fxMp7mkWn7d9kQ1KR+XUacpjCs/7O6XkREuqGZ3/0GKF2uw7AV6w38tQKWnHyh7foy3lNWWXb1jQ/tkm9pqdojy9jqVdW3EolnwcTV5ATa29z1wnLnMC8DHBBjXx8HvnNLzP5uA3z/t/gF+GSlGr5epgZT2bpUSwH7AI+7Xnin64UVJx4C3ykEvvM8UYJvV2BSnK9+wP5AWOzXuu38/JdENa8qtbdut3brAywXs423gWaFsoo9e+/9wPTST/PU5dz+RNf7beaEadsBI0u/E9prdbGIiHRTIwfOwxaOIBppvnjGnM/Dk/oqaMm4/7IdXrXWllMvedRev7i/R1c69l12GVVjrCldEsXaQFeKSDwLJq5eTqC9DYp/yjGMeLWt4q1Qkc31JJpe8799sPDMgB601hqsqXipw97AIcAnrhf+wvXCnq4XVtRU4DtNge88EfjO1sARwOdl/WBeuIZiv95xvfAs1wt7ldOvwHeagSfivFLodmvX9VkP7JJAS29CiRpJsmQbNcpSyPulX8RZjz4rnNrljt+YK0tvZD/mmzl36mIREenGBvd7HmvL+Jlh6qmt15TBRH9Wc1XpH+dmjZoVVzytKx1270FD98PQp8Q7ii20Fe7QRSISz4KJq/eICoLHsRywcZnbXh9jPxMD33kxZl8zRHWkFmpeg2HcDj15c616ZvdIUddmKx2BBXAD8DRwjOuFK8fpdOA7dwD9gEuhjFVUFu+yYr+Oc71w9TK2n168TiqxqeuFK+iWK1sjUXI3rjdQ4qr63fTveyhnCgR4PPDiul3muB+ZdjCY7UtuVyhcxsiB83ShiIh0cx99dT7Y10puZ8wA1ht0rgKWjLH+wAdsGbN3jDFn73vuU6t2jaMeZTCUXsXdmkfvu3yHN3SViMSzYOKqhXgjaubr53ph3eI2cL1waPGLeaUui9XDbC4FXLL4hwy01RheXb+e5wY0Mm3DRlprTZzk1ZZECawJrhf+NE73A9/5LPCd84ChwMVAnC9sA4A/A/e5XnhiiW3foPIi/j2Bo3XLlW1VYO2YbcwD3iWTtgpnlbtnZIFC/sIyXsSXpqHHXYwaVVP1x/zIi2uQSv2p9Ib2Y2bOvVEXiYiIcMQuzbTlD6esmQnmPMZP6a+gJcMUCr8tY7OlC6bu5q5wvK43eF8w/UoHJn+drg6R+BZMXDUBjyTQ5lZAfYltjo3R/ptA3OVEtwc2K/19KPozpyHFG+vWtYX9G6+pa7N/jLnvfsBtrhdOcb0wE6ehwHfeA0YRjXK7lrLXQlzkebva9cIXXC/cYxH7m0u0SmGhgvZri/uQ8myXQBvvADMUyi5iSP+/gy29UINhINvvd35VH+uoUYZU4x2YMmq82cLZGm0lIiL/sccWL0Lhd2X8vKwjVXM7Y8bUKWjxBZcMGmvh2dJhN3uOOOe5X1TzsQ7+1fieUFNyWqq19s0Pvsjdp6tDJL7/JK4C37HABwm0uRGLKSjtemEvykkaLdrowHdmxuxju5NP1vLWl/v3P3nM5QNPBVYn3mptDUB/otFX/3C9cDXXCyuaZx/4Tj7wnfcD3zkJ2Bx4iWj0XKXXwzbAw64Xhq4XrryQfv0RmFVh+5tWUBS+uzowgTbeIpN+W6HsQlrtCWBLF9s3KY/xU/eq2uPc4YDzMWa30g9mJvLsv1TbSkREvu/VDy/A2ldKb2i2oPcmngKWDJNvPdlaW/IX3CZlfr/3r5/ZrFqPs1fD0ucD65R+TSn8ZtKNx6pkh0gCUj/47/eAj2O2uTJRYmdRNgDWqPiLOEyM1btsbldg0wo+efD8/xP4zieB72wOHA9MiBmv/YlGxVzgeuGWcRoKfOe1wHe2AU4AxlF5Yg2iET/vA6NdL3QW2MdHQK7CNtcg/vS3ri8qzL5NzFYs0Ygr6UqG9XsDzCVlbFlDquZuxk/dtuqOcfy0w4lGkpa6wltpbTuBUaM0FVZERL7v5OEttLUdgS2jzqdJnUv9MgMUtPiCS3ecbOCm0luaXjU1NQ/s+6vxK1XbMbrnPrebtZxZxnvKy/eNnjBGV4VIMn6YuHoDSGKExpGL+bchRCOOKvFyAl/Gj6b99bVOIJP+n1UXA9+5hWhkzN4x+1UPnAc86HrhdcVRaZX/0Ij6dQDRSn5xigE2AGcCgeuFN7leuGLx7/0K21sWWLfS1RW7kXWIalzF0QQ8rFB2QR9+eSnWTi5jy56kah7g4WkbVc2xTZg6BJO6qaxtrb2I4VtM0QUhIiILNWzAS8DlJbcz1JX9s0dKav7umzOtLWMxJ2PWLTQsPfbA08Y0Vs0lddYTfSypvxljUqVeUgq0nQ765ZpIUr530wW+8x3wGvFqJQEct5h/G0BU76i9WoAnA9+pfBRRNrcOkG7np54B/rKofwx859vAdx4gGiFzHPBdjLitWmzjbdcLf+16YaUJPgLfmRP4TkA0JfEY4KsY/VqFKOE3xfXCc4BJwBcVtGOATYAa3XqLdUQCbcwGnlIou+LVsUszzfMOwPJNGVuvRF3qGcZN2WaJP64JU/eF1FgMpWuNWPs87z53iS4GERFZrNfev5BoVewSb6hmfQUrGQ9fM/w7Q+EosCW/TxrMwJYea46NakYt2fY644kVGmobHjGG0ivEW667b/QOT+hqEEnOwrLF04k3xQwA1wv3XMjfLQesWWGTc4C7Y3ZrU+B7P5hqClCft9QVLKmFP15vLu57sQLf+TrwnRsC31mm2M85Mfq5CnAp8IHrhZmYCax5ge/cDKwGXES00lylick+wGhgWow2dgN66NZbrCQKVk4nk1bB6q5qr23eBXso1pZzH65Ebe3jPDJtjyX2eCZMPQ6T+gfGlPNb188pzDuAY1UzQkRESjh5eAv5QnlTBiUxwehBjxWsvaicbY0xQ3rVLzNhz7Of7r2kHo97Tnb52oaGcRizeRmbzyi0ff5rXQUiyVpY4uppKi/uvaCzFvJ3GxX/VGJy4DtfVtybbC5FNNoqmoZnYNUv29gmN489np7DbmETA15vZpWv26ixQMoAvAI8RibdriRN4DsHAYOAO4GvY8RwJaIaWre6Xui6XljxbyMC32kNfOd8YCfgDuCjGP1aFcr4bcPCbY1GXC3uOt2OyqfSLugZBbOLG9z3IcqpBRXpRU3qASZM/y033FC7xBzD2GeWYsL0mzA110GpYfeApY18208Yus2HugBERKQsQ/tNBqtRup2s4c0PL7Tllq0wDKpL1T4z4pynN13SjmPfs57cxJqlXsCYrcvYvJlC/qf3XT5itq4AkWT9zxeFwHemEm+623zrFkdYLWhNKk94xM1c9ySq+QQp6PNFG870efT5oo2aAvScV2Cdj1vZdvo8nKlNLPdtWwu9UleRSVe00mLgO9OAw4HBRImiOA4G7iKqgbVDnIYC33kx8J0jgRHA7T/SdddXt96ifz4Wr9W4/qVQdgOD+/4Wa/9c5tY1GPMb1hv07BJR9+qRlwfSc9kpGHN0Wdtba7H2CIZu8YROvIiItMs3r12EZZoC0XnuuWdkYU7bdwdZa6eW9QFjNjem9iX3nIlHLSnH4J4z8ShbW/+8MZQ1ldQWCkcHl2wf6uyLJG9Rv+H+vwTaXp4FVkYrFuRercK2vg58Z1LM/jQSjfaBAmz6VgvGQj4F1kR/8qlo6uBK3+TZ6aWmGveBWXu4Xlhpnwl8pxD4zmSiqV9bAc/F6H9PYBfgUdcL73G9cN04wSjG8xjAIRpl15mO0K23ENncMkQ14FKx28qkpyqg3cSz/zyJQuG2src3ZltqUznGT7+G+8KVO72/4yavT3b6XaRqn21XTRFbOJUhfe/SCRcRkXYbObKVfP4IbPxyKNKOV9vLBs9K0boH1r5b5jtKT1LmFvfciQ/+mKOvRvx6YnqENzFLytyCMcuU+Z4yeuwlg+7UWRfpGIv6gvy7BNpuJEq0zFdDVLupEn9NoD+HRA9E6NVkWaqpgF3M2nYm6u8BwMeuF57reuFSle448J2WwHcmB76zPXAQ8DFQqLC5+mK/3nC98DLXC3tVukpf4Dttge88H/jOTsVz9RmQ74Tr7lDdegu1KrB2Au1cpFB2I6NGWW56/Wis/XvZnzHUkTIn0aPX20yYfhnjX96gw/s5buoAstNvpKb+NTAHY0x5z61opNUvGdL/ap1sERGp2B79X8YWRisQnetfo3f6lELzrta2Y+V6Y4aTqps+4tznrtv7V0+u01l93cd7Ziv33In3mFqmGczu5X7OUvhdMHqQp7Mt0nEWmrgKfOcroiRGHDWA43rh/ELcdcBmFbb1XALHun+Fn7OAT5QoOsz1wj5xOhH4zt3AusCVEGvIci1RHbFpwC9cL9wgZr+eBNYBLgYmd/B1Vx9nJFsXtiGQRALheoWym7lnZIEbXzsEW7iyXZ8zZimMOQtT+wYTpj/G+GmH+YLzogAAIABJREFU88CU1RPr18PTNmL81JOZMH0ytTWTwRxT1qqB/336tkLhMAb3/ZNOsoiIxDbzdZ9yp65JYoJLd3nPtrXtiLWvlP2KAjXGpI5L1de/7Z478cER3sS9hv3yofqk++ae8/SGI8557gz33HBaitqXMOYAMGUPCiiAP9YfdJbOskjHWlyR3jtYeIH19tgJ2IGowLgBlq6wnedj9SKbawA2mf+fLXXQVmuoa7PlLI03/8G1WjEm01wvvCfwnYsrfnj7TgtwluuFfwKGA9fFOLr1iomK11wvvCXwnStj9GseMMr1wpuK/bqQyqd3lrIJ8Iluwe9dowcSv3D9ZGCWAtoN3TOywD38ivFTX8PUXNeuBFE0+mlXjNmVxhRkp7+G5XEoTAfzBoXmN5j44EeMGrXwR+aYMXUsvcm6pAobUpPakEJqSwy7Yag80W/5jHz+APbor4UGRH4MxuzHhOkbdOljtHzIkL7n6WR3IyNHtjJ+yuFQ+2K7fk5KbPddvsMn7qlPbG97Nf7NwLB2vKKkgOEGhjcss9ycEd7EJ4y147H2hVZbeP3BS3ecWW5be53xxAqmvmHzmhR9LWyJNbtjWLuSqSvW2hZjOeW+SwbqF8YinWBxiatxxE9c1QBDXC98nGiltJUqaONt4KuY/VgTWK74kkJrveGL5WpY49M28u1PE/QDNne98BDg1MB3Hqm0U4HvvO964Q1EUyEvAY7nv4my9toUuNz1wp8BXuA7D8bo10fATa4XjgPOAE7pgGtvS+Bx3YL/0YOomH9cWaBZ4ezGhvS/hXFT3qKm9q7KE0dmUwyb/iePWtMDtt/fMmH/OcDs4p9aYCkwvTAUR9amvvc/lX+ZtE/ROvdghm/3kU6oyI/EmAFEdRe7MPsKoMRVt/s5ucVUJky/GMyFCkbnCv6wy7cHHjhmr5YN1/SN4dftGdlUfDD1MrAnxuyJgTpqcL2Jn2GZAeY7sLOtYbbBpqxNNRpso4VlwKxmsKthzH8WQDLE+NZl+cjYwgEqxC7SeRaXuJoEfE7lqwDON4Joqp2Bin6z8QAwN2Yf1vresRbgpU0bWPmrPLV5u9haV4tQQzRiaJzrhU8WEw4fBb7T1u4HuO9YohEyJ7peeClwM1G9qUqGwqaA/sADrhdOKvbrtcB3KqqnFfjOB8Cprhf+DrgJyFR4DhdmY91+3/PzJN7AgRyZtAqPdnd7bPEkDzydpqH3VRhzREJfYg2wVPFPR32JbAZ7Hje+/nvuGVnQiRQRkQ7xznOjWW+QW0zQSie6J/r5fs7eZz87viaVugNj1oz5grIKZn4dZVPMRZliSswskJsyifTfWvu3VMt3p/zriiFf6GyKdJ7F/V68CUhiBacNgfWJRpRUkgSbGPhO3C/i2/3wL/I1hie26cHny9dgDdTkbaVt7wzMAC5wvXDrOJ0MfOeDwHeGEq1C+DgwJ0ZzWwHTgUtdL9wmZr8+CnxnOLAv0YieeQlcF/11+33PIQm08SFoqWcp2mvHmQzueyTW7gn2/Sro8YM05/uS6XeFklYiItKhjj22jbaWw8G2KBg/jvsv3f5x5jb3LVh7NZa2Jb7D1r6LbRs2dvTAg5W0Eul8i0xcFZNFD5PMtKMTiaaWtDfVPQv4NIH9b7Gwv/yuV4rn+zbyfN8efLZCLQ0tNs4+zgPuc73wTtcLe8VpKPCdO4D9in/iFKY3wJlA4HrhX10v3Cxmvx4s9mkv4k/zW1u3X1E2tybJTMd4hUxaBUfl+wb3fYgPv9qIQv4UsEtiXbmXyBeGkUnvxZ5bvKkTJiIinWLYVtMpWK3E/CMK/rDLt/eNHnhKnpYtbfS9c8lj+ciSP3nmx//eNBi9wzidNZEfR6lKJC8U/8R1JNHUt/ZOM3u/+CeuDRfxIKKtxvDpCjWEA3owsV9jvqUu1jDS1YhGznzieuFvFlhRsf0Pct+ZGfjOeKJpg8cDH8fo1+rAT4GnXC883/XC+hj9+i7wnUeBvYF9gA8qbKrB9cIVdQsCkMTyufOA/1MoZaGO2KWZIf2vpmnG+hTsGVj73o/7Emgt1j5WTFhtw9B+ehEUEZHO9+7ES7FMUiB+XPeP3mn6WN8ZDnZbrL3PWvujj7y22FzBFk6c+fHr64/1t7/miduPUA1ZkR/RYhNXge98SzT1yCawr9to/4irT0hmxFXJudNtwPt96r6dMLDncGAU8epqLQ38FnjP9cKfxhmBFfhOa+A71xOtHngh0ci1Sq1QbOMj1wtPcL2wLka/5gS+c3/gO2sBf6mgiXqiAu3dWzbXkyipGNe3wBg90mSx9t67iSF9f8+z/1yXtkIGy53EryHYjrdAO4OCvQzbthGD++6uhJWIiPyojj22jdbCEZoyuGQI/IEvBqMHjmhttutaay8mKsfSiexn1nId2G3H+gP73jd60J+VsBJZMpSz9tPjJFPTaE+gZ3ueHMDHge80JbDv8hJmBWa11pkPAt+5kGjq1t+JkmeVWoloxcCxrhdmXC9ctvIHudMc+M4oYBuiRFGcERMrAtcSjcAa7nph75jxvamCz9QSJeO6u1PbeV8syiNk0nmFU8oyapRlj36PMjj9M+bMXAVbGIG1V4GdAon+lnMO1j5GwZ5PS9sABvddlyF9z2bIgLd0EkREZIkwvF8Oa7XC4BLkoSsHvT929MDfBL6zLvnWrQq28Ftr7TMkvXK2tTOttY/Zgj23zbZsGfiPrDZ2tHNC4A98UWdBZMlSMqFTHJXzOdC7k/uWB64IfOfsWK1kc6sDr5TZ/5cAl0z6owWOfwAwEjg75vHMA54Hfh/4zn1xg+N6YT+iVQNPj9nUXOBl4JrAd+6usC9rUNmUwVsC3zm629592dwywFii6aCxX7vIpB9GJK5xE5cj1XMLrNmAlNkQ7IZg1sKwNNALWApMLywWQzPWNmH4BsunGPMJtvA22FfJ8wrvhdM59tg2BVVERETiOvC0MY2tjX22KEA6hdkMY9YFVsOwGpZlLKYRbD2GvLE0Wcw8oAnsl8CHBj6ylg9J8VqhuWXK/VfsPENRFakOZY1Ecr3wb8BBndy3VuA3ge9cFjM5sDlRgfNlyth6PFHiqukHx18LrAPcyUJWKGyntmKy4ozAd2LVmXG9MAX0Ba4GdorZr2bgGeDEwHf+3c5+LAW8QVTjqz3+HvjOT7vt3ZfNbVe8FlaJfa9k0vWIiIiIiIiIdDG1ZW53JJ2fuCoAXyXQzlrtOM7Pf5i0Agh8pw14C3BcLxwGXE9U8Ly2wpjvD+zveuENwMWB73xYyYEFvlMApgI7u164E/BHoD/tryUG0ADsDuRcL/wrcBIwO/CdcuqbzQG+pv2Jq57d9s7L5lLAzsRPWkE03VBERERERESkyymnxhWB78wD7u7kvrUCryfQTnvqtTSVEYuHA99Zm6jI+Ssx+3Ys8JLrhce5XrhOnIYC33mKqP7VuUQF9StVCxwGzAKOd71w3TL2bYFKlrHvGWflxSq3EnBBAu3MBm7Xo0xERERERES6olQ7tr22k/tWAL7sxP3lgbJHPgW+czFRwflfENUAq9QqwHXAfa4X+q4XNlbaUOA7bYHvXArsAxxF/JU4rgUecL3w98XpkoszpYL2l6G8KZxd0TEkM+LsFqLppyIiIiIiIiJdTnsSV9OJ6hh1FksyqxmWqxV4uz0fKNaouplodbwriJdA6EtUAP7t4nTEihX7dTuwBXB5zH5tBpwCzHC9cORitnu3wusv1e3uumyuJ9FUzLhagMfIpLWEs4iIiIiIiHRJ7anR9C1wFdHooM7QBrzfYQduoaHJUpe3NPU0tNaafAE+a287xWlyc4AzXS/8M/B7YChQyRS4FFHtrIdcL5xINO3v6cB38hX261vg164X/gH4A+AC9RX2qw9wt+uFZwEnAy8GvtO6wDaVTOtcrvjnk252340gmdpWrwCT9BgTERERERGRrqpdRbxdL9wMeAhYuxP69mXgOyvFbiWbGwrcy/xpWSlY/psCW74+jxVn5imkojD8e+26ObV5e9CkX279QNxdul64P3A8MIjKElgLug34MzD1B4miSvo1CPgt4BAtax/H9cCtwEuB71jXC9em/VMTZwD7BL4zvdvccVFR9neJFg2IwwKXkUmfo8eYiIiIiIiIdFXtmqYV+M6rQLb4pbmjJbWPeuYn6FLQe1aB7aY3sezsAvPqDS21hpZa2PD9lp5rftp2s+uFd7leOKDSnbleaALf+ScwHDgAeDhm/48ExgK3u164RZyGAt95jmi0z/7AX2P26zjgEeBe1wv7EtUHy+uWKul0otFrcX0DXKlwioiIiIiISFdWSX2hcUBzFR3jpP/018L6H7TQ0GrJ/+DI22qMIZq+dTDwrOuFV1Sys+IUPQLfaQl85yGiRNGeRImGSq0O/BR43vXC0XFW4gt8Z07gO48QFW8fBnwUo1/LEU0/DIlqar2vW2oxsrkVi9dDTQKt3Usm/aWCKiIiIiIiIl2ZqeRDrhe+R/ypTqV8EfjOyrFbyeZWA14FetfmLdvm5rHy12UPDPoaOAv4Z+A7M+N0o7gq30nAaQnE7hvgPODmwHdaYvarkWha4wVEK/yZTrz+ZtCdpgpmc8OBfxB/+ihAXzLpnB5hIiIiIiIi0pVVmrg6nGiETUdKJnEFkM19AaxYQeJqvunAOcCTge/MjtMV1wtXBi4F9gBWi3lk0wGPqID7zLhhcr3wRqIpjn066fqbQXdJXGVztUTTMw9MoLXHyaR30+NLREREREREurpKpgoS+M4dwEtVdJwtAG11htbainJ1fYEHiOo5HRKnI4HvfB74zlFEU8b8+X2rUF/gn8A9rheeGDdIge/8AtgbOL8Tz43tJvfaMJJJWkE0Qk5ERERERESky0vF+Gw1rWb2+fz/826fujhz4QYDt7pe+KbrhevH6VDgOy8STc9bG3gxRlN1QAa4yvXC510v3CBmv14GRgNrAGM64dyYLn+XRSsJXptQa7cQrUooIiIiIiIi0uVVnDRwvXBp4AVgkw7qW5JTBf8GHARAnWH9d1ro92axXnu8tMnNwOXAW/OLsseI5+7AxcA2xC/efStRDazPAt8pxOzXTkSr1/UjWqExSdOJpgrO6NJ3WTZ3KPCXBFpqBg4ikw706BIREREREZHuIM6Iq9kkN4qko736n//Xanl73Xpe3rSRWUulMICpPOV0NFHy5XTXC9eJ08HAdx4NfGcgcALwcszjPQr4GDjH9cK1Y/brqcB3tgF+AUxN+LzMLf7purK5nkSJvyTkgOf02BIREREREZHuouLEVXGE0d3A5A7qW5K1j1753n+1WWasUcczA3owadNG5vRM0dBiK91hA3AFcJ/rhaNdL1wuTkcD37kR2IcoKRY3UXQxMM71wt+5XrhCzH7dAQwBDgOmJHReviv+6cp+C6yUQDutwPVk0p/rsSUiIiIiIiLdRZwRVwS+8wVwP5DvgL7VuF6YVP2jt//nb/KW5jrD+6vW8ti2PXkx3UB9m22KsY++wFnAe64X7hMzrh8STfdzgLNjxncT4DTgNdcLfxmzX58HvvMXYHvglATOS3PxT9eUzW0G7EcydbzeJpO+WY8sERERERER6U5if6EuFikPgRUT7ttXwEpxa0cBkM31Ad4Aei5ym1oetbtMGravt/FfgD2AZWPu9WXgTODJwHfaYsZ4PeBc4GCgR8x+TQZ+BYSB7zTF7NfywO8AF1i+gibuCnzn0C55Z0UF2c8mWjkyCQeTSf9NjywRERERERHpThIZ0eR64dXALxPu29fA2oHvzE6ktWzuA6KV8hblbDLpy4rHswXRynq7Ao0x93w3US2wZxIo4L410WqOe7C4JFyZEQE8YHJCibVrgOHt+FgeuCjwnQu75J0VjbaaTsxRjUXvkEmvj4iIiIiIiEg3k8SXagLfORn4MOG+1ZBMbaD53i91GAsczxSiOlMjgXti7vcnwFjgL8UV+uLE+SWi1RH3A/4as18Z4FHgVtcLB8fs1zvAke38WAswrQvfW9cndX8BR+hRJSIiIiIiIt1RKsG2Dk+4bzXAqgm2Fyzm3yaQSf/7exv7TlvgO/cDPwM2AmbF2PdywCHABNcL/+J6YV3FB+E7rYHvPEK0cuBWwIwY/VoKOJSosPy9rhfGGV02sJ3btxB/9cQlUza3F7BjQq3dSDQVV0RERERERKTbSar4Oa4X9iKafuYk1ORcYP/Ad8Yl0lo2ty7wzkL+5W2gL5l0UxnHeCZwIrB2zN58A4wC7gh859sEYn8aUd2qVYgSfpWaBVxY7NdX7ezDBcVjKtdnge+s2uXuqGyuAfgIWCGB1r4DDiCTHq9HlYiIiIiIiHRHiY24CnxnDlFdqEJCTdYCGyZ4rDOB1h/8XQ5wy0laFY/xd8DGwJ+B92L0ZTngj8Bk1wt/Xkz6xYn9VcAGRIXAP4rR1DLAlcBLrhf+1PXC9kzVHNTOfU3qovfUTSSTtAJ4DnhKjykRERERERHprkySjble2EBUE2rvhJrMAj8JfOfr+C3lGoE/ERUQnww8DdxLJv1mhcfan6gG1slEU+7ieAr4P+C2wHcKMc/B5kR1tY4h/lTLZ4E7A9+5vsQ+DfAKsGk72h7V5QqzZ3PbA/cTJSbjagN2IJN+Xo8pERERERER6a5M0g26XpgB7gN6JNTkScCf467IB0A21xNoAJqBZjLpfMxjrSVKWl1HVDQ9jhaiAvcjA9+ZlEC/lgcuIaqFFUcr8BmwT+A7Ly9ifysX+96e2l27B77zWJe5k7K5eqKC+fsn1OKVZNK/0iNKREREREREujPTEY26XvgUyRWnBtg08J3Xl+RAul44ELgC2Ib2JXAW5uZiW28FvhM3ubY7Ue2prYHGmP36e7GtdwLfaV1gH7sAj7ezreUC35nZZe6kbG4kcHdCrTUBa5FJf6lHlIiIiIiIiHRnqQ5q93Agn2B7Ny3pgQx8Z2LgO9sXj/2FmM0dDUwBrnK9cOOY/Xo08J0dgQMS6NdBwKvAla4XLjgt8JR2tvN8F0tabUBySSuA05W0EhEREREREemgEVcArhceT1TEPCmXBb5zdjUE1fXC1YA9gOOAbWM29z5wJ3B74DtvxuzX0kT1r35O/NUf3yWqZ/Zn4EWgPYXcu9o0weeAgQm19hgwlEy6TY8nERERERER6e46MnG1DDAe2C6hJucCRwW+c3e1BNf1wp5Eo5RuidlUnmhVxKsC3/Fj9skAPYlWAbyXeIXlC8V+9ab80XvfAuslUnB/SZDNXQmcnlBrs4GfkEk/pEeTiIiIiIiISAcmrgBcLxxOtMpaUlMSnwP2rrakR3G1xeuICncvHTPuLwG/AZ4MfKcpZr+WIyrgfiBRMffOcAtwYuA7zVV/92RzA4F/Aask1OIDwEgy6SZEREREREREpMMTV4YoUXFkgs1eHPjOb6ox2K4XbgScCRxC/FUXnwEuBB6Nu+Ki64UbEiXDRgDLdGAILHBY4Dt3Vv2dk80ZIAD2SajFL4FdyaRzeiyJiIiIiIiIRExH78D1wg2IaiD1TrDZoYHvjK/WoBdX4TuOaKRTnNFo84CxwE2B7zyaQL92JUoy/qyDDv0dYJ/Ad16p2jsmmzNk0pZs7mLAS7Dlk8mkr9EjSUREREREROS/TGfsxPVCHzg3wSbnBL6zVDUH3vXCRmAj4HZgQMzmvgNeA/YPfOfDmP2qB9YmKrzeP+HD/kfgOwdW/V2Tze1FNAU2Ka+TSW+qx5GIiIiIiIjI95nO2pHrhe8A6ybY5PTAd/p1hZPgeuHZwNHAOkBNjKbmAecDtwJfJzCF8KfAaGANoDbmYc4B3MB3slV9srK5ZYBXijFJyupk0p/ocSQiIiIiIiLyfalO3FeGKLGSlL6uF15Z7SfA9UIT+M6lwJbA2cBbMZprBC4HpgInuV64apy+Bb7zN2ATotFycWsvPdUFklYNwG0km7Q6FfhUjyIRERERERGR/9WZI65SwHlEBcWTMhvYt+oTIt+P07rAYcCxwGoxm3sZuB64I/Cd5mKSzFbYr7WBQ4FTgJUqaGKXwHeerNoTExVjPxn4Q4KtvgwMJZP+Qo8iERERERERkf9lOnNnxfpJDwO7JdjsbGD1wHe+6yonxfXCGmBl4JfAOTGbawU+Bk4NfCeI2a8U0VTGT4AV2vHRiYHvDKrqk5LNrQe8nWCL84iSVk/pMSQiIiIiIiKycKazd+h64VbAo8CyCTb7SOA7e3TFE+R64ZbAn4AtgB4xm5tANGro3cB3mivsz0VEybT21OLqHfjOt1V7ErK5pYiSdUkuCPBnMukT9QgSERERERERWbRUZ+8w8J1JRNPXkjTU9cKLu+IJCnxncnG0kguMA+IUXB9MVP/qatcL2z0CyvXCjYmmC7YnaXURUWH2avYvkk1avQacpMePiIiIiIiIyOKlfqT9ngM8kHCbnuuFXTYZEPjOeGA/4CDghRhN1QO/AB50vfAPrheu147Pnkq08mG5PgTuDXynrSqDns2lyOYuJVpYICktwJFk0hYRERERERERWSzzY+3Y9cI1gOeB1RNsdjawR+A7z3blk+Z64dLAIOAu2ldramE+A4LAd44rsc/DgDva0W4bcH7gO5dUbaCzuYOLx1ybYKvHkknfqEePiIiIiIiISGk/ZuIqBRwHXJtw0x8D2wS+83FXP3nFIu7XAgcAy8c8n81EI7qeDHxnzg/2szmQa2d7Lwe+s2XVBjeb25Qosbp0gq0+DBxEJj1Ljx4RERERERGR0syPuXPXC3sANwMHJ9z0C8DOge/M6w4n0fXC9YHTgX2B1WI29zRRMuyewHcKrheuSlRMf7N2tNEGpAPf+XdVBjSbW5soabVKgq1+AexKJv2KHjsiIiIiIiIi5TE/dgdcL1wJmAisn3DT9we+s093OpnFFQhPBn5GVL/MxjjHY4G/ExVj37Odnz0o8J27qzKI2VxvokRd0qPFXDLpsXrkiIiIiIiIiJQv9WN3IPCdL4imukG8FfN+aC/XC//UnU5m4DuTgWOAzYExxEtMjgBuB/Zo5+cuBf5RlQHM5lYA/kbySaurlLQSERERERERaT+zpHTE9cJDgDsTbrYJOBz4R+A73W4VN9cLXeAqogL49Z2wyxDYL/CdT6ouWNlcLXABcF7CLU8CdiCTnoeIiIiIiIiItEtqCerLX4FbE26zB/AXwO2OJzfwnQDoB5xBlFTqSDOAE6syaRU5nuSTVu8DP1HSSkRERERERKQyZknqTLEQ+AQgnXDTs4B9A995rLueaNcLlweOICri3ifh5luAwYHvPFWVwcnmTiD51S0BDieT/j89ZkREREREREQqY5a0Drle2J+oWHuPhJv+Bji+aouGJxNbA6wKHEZUiyopuwW+83hVBiWbOxK4BuiVcMsXkEn/Vo8YERERERERkcqZJbFTrheeDVzSAU2/Bewf+M607n7iXS9MEa0cuBtRkrCSa6EA/DTwnTFVGYRszgXuAWoTbnk8mfRQPV5ERERERERE4kktaR1yvdAEvnMpcEUHNL8B8FfXCzfr7ic+8J1C4Dt7E61CWEkNJgucVsVJqx2JpgcmnbSaDByqR4uIiIiIiIhIfEtc4mqB1f/OJirYnrTNgX+4XrhSdz/5rhfWA0OAhgo+fkzgO1dX5YFnc0OBe4lWW0zSp8DRZNJf6NEiIiIiIiIiEl9qSe1Y4Dt54EygI6b1bQo863rhet31xLteWANcBBxewXVwYOA7t1TlgWdzGaKE6IoJt9wKnEIm/bIeKyIiIiIiIiLJSC3JnQt852NgKNFIlqRtCNzreuFa3fTcHwSc1c7PfAvsFPjOP6ryiLO5nYC/Act3QOt/JJMeg4iIiIiIiIgkJrWkdzDwnU+BI4lGtCStP3Cr64VbdqeT7nrhycCdRHWqyvU6MDLwnaer8qCzuR2Av5D8SCuAG8mkzySbM4iIiIiIiIhIYlLV0MnAd8YRjRDqCLsDD7heuHl3OOHFpNUfiv9ZbqLlaWDvwHfGV9XBzk8kZXN7ENW06ojRdXcBpwGQSVtEREREREREJDGpKuprAJzbQW2vBjzqeuHArnyyXS/cF7iU8hNWAH8C9gl8562qO+BM2pLN7U80PbAjivGHwK/IpOfqUSIiIiIiIiKSvKqa2uR6YQ+iJMSIDtrFe8C+ge90uQLbrhf2pX2F7ucAvw985/yqPehsbj/gHjomQfspMJRMehoiIiIiIiIi0iGqacQVge80AT8hmvbVEdYG/uJ64e5d6SS7XujQvqTVROAnVZ60Oga4vYOu8c+BvZS0EhEREREREelYVVlM2vXCnsA4YMcO2sUs4MTAd+6s9hNcTMLdBaxSxuYWuAS4MvCdr6v2oLO5iwGvg1qfDQwjk35Gjw8RERERERGRjlW1q6C5XrgCcAewZwftYg7gA5cGvmOrNEY7AP+gvKTV28AvAt95rGqv5myuJ/BH4AigtgP2MBs4hEz6Pj06RERERERERDqeqebOu164ETAW2KQDd3MBcHngO/OqLDZrAtOBZUtsmgf+GvjOYVV9JWdzvYEbgQM7aA9NwK/JpK/RY0NERERERET+v707jbWjrOM4/j1dgUIB2YSqoAVBOmVxIaNgNDC4BINDSxWJYFBB0JQiArWdigUZLRSL0EBYJCrKIlvHhFiEsUCJMAEbxA6riFRACnEjgVvscq8v5pqQ2lJ6uWeb8/28PNt/nv8zZ1788swzao0R3XzwWRo+CXwReLSJZc4BLomTYrdu6UucFHsDv2HTodUSIK5BaLUf1X5WzQqt1gGzDK0kSZIkSWqtRh0GMbjyajkwpollCuC4LA2f6vBe7AMs4o1Xob0EzAAWZ2n4cldPfl5+ArgC2KOJVb5BFFzm5UKSJEmSpNZq1GUgcVLsCdwLvL2JZf4CTMvScFmH9mBvqicu7ruRj6wFLgfOy9Lwxa6f9Lz8OvB9Nr2ybKj6gdOAy4iCdV7c04SMAAAIQElEQVQuJEmSJElqrUadBhMnxUHATcC7mlzqY8B9WRqu7aCx7wLkQLCBt9cBzwJTsjR8qOsnOi9HA3OAs5tYZQ1wPlHwHS8TkiRJkiS1R6NuA4qT4kPAT4BJTS41H1iQpeHKDhjzbsB1VIHa+h4DbsrS8Lu1mOC83Au4AIibWGUtcBFRcJaXCEmSJEmS2qdRx0HFSbEHcDewe5NL/QE4MUvD37dxrDsAtwHhBt6+ALgsS8MVtZjYvDwKWEBz97MC97SSJEmSJKkjjKjjoLI0fAY4GCibXOoA4J44KY4HiJOipUFgnBQ7Axn/H1otBfYHZtcotJoH3EJzQ6s+4BiqfcAkSZIkSVKbNeo8uMGnDS5i45uVD6drsjT8UgvHNp4qyIkGXxoA/g7MyNLw+tpMYl7uShXE7dnkSq8CpxMFV3pZkCRJkiSpMzTqPsA4KfYBfky1AmugyWO+C5iZpeGDTR7TdsA5wKmDL60Ebqd6WuCfazFxeTkKmEK1l1izN9tfCcwhCq72kiBJkiRJUudo9MIgB5+4dy5wUgvKvQhcn6XhN5s0ltHArcBnBl+6hWovq2VZGq6rxYTl5XbAtVSrycY0udqzwDFEwX1eDiRJkiRJ6iyNXhlonBRbASlwWgvKDVDtrxVnafj0MI5hJHADcDTwN2AWcG1tAiuAvJwKLAR2bUG1FcBniYKHvRRIkiRJktR5Gr024Dgp5lPdYjemBeX6gROBX2RpuPotHvcYqlVjM4EfArOyNFxTm4nJy52AC4HjW1TxGeAjRMELXgYkSZIkSepMjV4cdJwU36YKgLZrUcmFwM+HuvdVnBRbUK0UO5IqsLqnNpORl+OBw4F5NH8D9v9ZDBxNFPR5CZAkSZIkqXON6LUBx0nRyNJwHjAVeLxFZacDt8VJMXcIxzsSOAZ4DPhUzUKrycDNwI20JrTqB+YCUwytJEmSJEnqfI1eHnycFJOpNjpvRWjyLyDM0vDJzTzGBrBllob1CVrycmtgNnAGMLqFlWcQBZf4t5ckSZIkqTs0er0BcVKMA5YCBzaxH+uAiVkarujpZuflSKo9rH4A7NLCyq8BhxIF9/uXlyRJkiSpezRsQSVOikupQpWth/mn/wkclaXh0p5tbl5uBYTAycC0Fld/AIjdhF2SJEmSpO5jcPU6cVJMAS4Hdhqmn1wJHJ+l4Z0929S8nAJ8GTgE2LbF1X8EnEcU/MOzW5IkSZKk7mNwtZ44KXYH7gF2f4s/1Q+cnKXhVT3ZyLycAMwHPgeMbMMRzCQKLvCMliRJkiSpexlcbUScFNcBXxji1weA6VkaXtpTTav2sNoXmEMVWLXDCmAqUbDMs1iSJEmSpO42whZsWJaGxwJnAv/ezK8OADOyNLx08ImA9ZeX25KXBwOXAH+kfaHVIiA0tJIkSZIkqR5ccbUJcVIcBJwPfPxNfiXJ0vD7PdGcvBwLTAc+CRwA7NimI3kZOAVYRBS85lkrSZIkSVI9GFy9CXFSjAHOBWZu4qMLsjT8VtMPqHpK3yqiYKAtDcnLbYBTqVakjQNGtXF6llE9NfA5z1RJkiRJkurF4GozxEnxaWAhMHEDb9+UpWFzb5Gr9pCaClwMPA9cA9wCvEQUrGly7fHAJGAGEANj2zwdfcBVwJlNH7skSZIkSWoLg6vNFCfFXsACqtvjRg++fHOWhtOaVjQvG8CBwGyq4Gp9C4E7gEeAvxIF64ap7vbAnsD+VIFV0CHT8DAwjyi4wTNSkiRJkqT6MrgagjgptgCOBM4GngCmZWnY35RieTkRmEUVlL1jE59eDjwKLAVuJQpWDqHeCGAa8GFgMlVYtXOHtP4/wPeAnxIFz3smSpIkSZJUbwZXb0GcFNsAa7M0XNWUAnl5AnAhsP1mztVqqlvpVgDnAYuJglffoM4oqlDsdODzwHiqWwE76fx4imq12fK27e0lSZIkSZJayuCq01QrnvajCqwOG8Zfvhe4m2pPrOeAMcARQAR8FNitQzvyCjAXuIgo6PcEkSRJkiSpdxhcdZK8nACcAiQ2g9XAXcAZREFpOyRJkiRJ6j0GV50iL2cBx9I5G6C302LgaqpbHPtshyRJkiRJvcngqt3y8oPAzcAEYFSPd2MN8DXglwZWkiRJkiTJ4Kpd8nJnYDYwHRjR493oA64H5gzpSYiSJEmSJKmWDK5aLS93BA4HFgI79Hg3+qg2jJ9NFDzsySFJkiRJkl5vlC1oufcCVwHjerwPVwK/Au4kCtZ4WkiSJEmSpPUZXLXeA8CuwGnAuT04/iXACcBKomC1p4MkSZIkSdoYbxVsp2qfq7OA44C3Uc8gcYDqlsD7gflEwR1OvCRJkiRJejMMrjpBXo6j2qT9OGDfGo3sBeB24GL3sJIkSZIkSZvL4KqT5OU7gUOBw4BjgZFdOpIHgBuB3MBKkiRJkiQNlcFVp8nLBjAG2BY4BZjbRUe/HDgJKIE+oqDfCZUkSZIkSUNlcNXp8nI08FWqFVjvB7bsoHlbTXU74K+BK1xdJUmSJEmShpPBVTfJy0lUK5oOAfanfbcSPg08CNwGZETBK06OJEmSJEkabgZX3SgvJwAHApOBg4EjWlD1MWAJUAAPEQWPOBGSJEmSJKmZDK66WV6OBMYCWwAR1X5Y7xvGCv3Az4DzgZXAKqJgtY2XJEmSJEmtYHBVN3n5buArwAeAfYCdqIKtN7qtcAB4DXgVeAZ4CLiBKFhiQyVJkiRJUrsYXNVZXo4F9qO6lXASsDcwEdhq8BN/Ap4AVgC/BX5HFLxk4yRJkiRJUicwuOolebkH8B6qVVirgCeJgsdtjCRJkiRJ6kT/BUaJWSieE29KAAAAAElFTkSuQmCC" alt="" data-rotate="" data-proportion="true" data-size="511px,130px" data-align="none" data-file-name="logo.png" data-file-size="40338" data-origin="," origin-size="1198,303" data-index="2" style="width: 300px;">
                                              </p>
                                          </td>
                                          <td bgcolor="#ffffff" style="width: 300px; padding:20px 20px 15px 20px; background: #ffffff; background-color:#ffffff; text-align:center;" valign="middle">
                                              This email is automatically generated.
                                              ${entitiesNames && entitiesNames.length > 0 ? `<br><i>Scope:</i> ${entitiesNames}` : ''}
                                          </td>
                                      </tr>
                                  </table>
                              </td>
                          </tr>
                          <tr>
                              <td valign="top" style="height:5px;margin:0;padding:0;line-height:0;font-size:2px;"></td>
                          </tr>
                          <tr>
                              <td valign="bottom" style="height:5px;margin:0;padding:20px 0 0 0;line-height:0;font-size:2px;"></td>
                          </tr>
`;
};

export const footer = `
                      <tr>
                          <td bgcolor="#f26422" style="padding:20px 20px 15px 20px; background-color:#507bc8; background:#507bc8;">
                              <table cellpadding="0" cellspacing="0" style="width: 100%; border-collapse:collapse; font-family:Tahoma; font-weight:normal; font-size:12px; line-height:15pt; color:#FFFFFF;">
                                  <tr>
                                      <td style="width:340px; padding:0 20px 0 0;">
                                          OpenCTI, the open source threat intelligence platform<br>
                                          <a style="color:#000000; text-decoration:underline;" href="https://www.opencti.io">www.opencti.io</a>
                                          | <a style="color:#000000; text-decoration:underline;" href="mailto:contact@opencti.io">contact@opencti.io</a>
                                      </td>
                                  </tr>
                                  <tr>
                                      <td style="padding:20px 0 0 0;" colspan="2">Copyright &copy; 2021 OpenCTI.</td>
                                  </tr>
                              </table>
                          </td>
                      </tr>
                      <tr>
                          <td valign="top" style="height:5px;margin:0;padding:0 0 20px 0;line-height:0;font-size:2px;"></td>
                      </tr>
                  </table>
              </td>
          </tr>
      </table>
   </body>
 </html>
`;

export const sectionHeader = (name: string, number: number) => {
  return `
    <tr>
        <td bgcolor="#ffffff" style="padding:10px 20px; background: #ffffff; background-color: #ffffff;" valign="top">
            <p style="margin: 0 0 10pt 0; padding: 0; color:#999999; font-size:8pt;">${name} (${number})</p>
  `;
};

export const sectionFooter = (number: number, word: string) => {
  return `
            ${number > 0 ? `<span><i>And more ${number} ${word}...</i></span>` : ''}
         </td>
    </tr>
    <tr>
        <td valign="top" style="height:5px;margin:0;padding:0;line-height:0;font-size:2px;"></td>
    </tr>
    <tr>
        <td valign="bottom" style="height:5px;margin:0;padding:20px 0 0 0;line-height:0;font-size:2px;"></td>
    </tr>
  `;
};

export const containerToHtml = (url: string, entry: StoreEntity) => {
  const fullUrl = `${url + resolveLink(entry.entity_type)}/${entry.id}`;
  const author = entry.createdBy?.name ?? 'Unknown';
  return `
        <p style="padding:0; margin: 0; line-height:140%; font-size:18px;">
            <a style="color: #f507bc8; text-decoration:none;" href="${fullUrl}">${entry.name}</a>
        </p>
        <p style="color: #999999; margin: 0;">By ${author}, ${prepareDate(entry.created_at)}</p>
        <p>${entry.name || entry.attribute_abstract || entry.opinion}</p>
        ${
  entry.objectMarking && entry.objectMarking.length > 0
    ? entry.objectMarking.map(
      (marking) => `<span style="background: ${
        marking.x_opencti_color || '#f6f7f9'
      }; border-radius: 4px; padding: 3px 6px; margin-right: 6px; font-size: 12px; color: ${
        marking.x_opencti_color === '#ffffff' ? '#00000' : '#ffffff'
      }; font-weight: bold;">
                  <span>${marking.definition}</span>
              </span>`
    )
    : ''
}
        ${
  entry.objectLabel && entry.objectLabel.length > 0
    ? entry.objectLabel.map(
      (label) => `<span style="background: ${
        label.color || '#f6f7f9'
      }; border-radius: 4px; padding: 3px 6px; margin-right: 6px; font-size: 12px; color: ${
        !label.color || label.color === '#ffffff' ? '#00000' : '#ffffff'
      }; font-weight: bold;">
                  <span>${label.value}</span>
              </span>`
    )
    : ''
}
        <hr style="margin:15pt 0 10pt 0; color: #f6f6f6; border-top: #f6f6f6 1px solid; background: #f6f6f6"/>
  `;
};

export const relationshipToHtml = (url: string, entry: StoreRelation) => {
  const fullUrl = `${url + resolveLink(entry.from.entity_type)}/${entry.from.internal_id}/knowledge/relations/${entry.internal_id}`;
  const author = entry.createdBy?.name ?? 'Unknown';
  return `
        <p style="padding:0; margin:0; line-height:140%; font-size:18px;">
            <a style="color:#f507bc8; text-decoration:none;" href="${fullUrl}">New <i>${
  entry.relationship_type
}</i> relationship</a>
        </p>
        <p style="color: #999999; margin: 0;">By ${author}, ${prepareDate(entry.created_at)}</p>
        <table cellpadding="0" cellspacing="0" style="width: 100%; border-collapse:collapse; margin-top: 10pt; font-size: 10pt;">
            <tr>
                <td bgcolor="#ffffff" style="padding:0; width: 35%; text-align:center; background:#ffffff;background-color:#ffffff;" valign="top">
                  <span style="color: #999999">${entry.from.entity_type}</span><br>
                  ${defaultValue(entry.from)}
                </td>
                <td bgcolor="#ffffff" style="padding:0; width: 30%; text-align:center; background:#ffffff;background-color:#ffffff;" valign="top">
                    <i>${entry.relationship_type}</i><br>
                    ${truncate(entry.description ?? '-', 60)}
                </td>
                <td bgcolor="#ffffff" style="padding:0; width: 35%; text-align:center; background:#ffffff;background-color:#ffffff;" valign="top">
                    <span style="color: #999999">${entry.to.entity_type}</span><br>
                    ${defaultValue(entry.to)}
                </td>
            </tr>
        </table>
        <hr style="margin:15pt 0 10pt 0; color: #f6f6f6; border-top: #f6f6f6 1px solid; background: #f6f6f6">
  `;
};

export const entityToHtml = (url: string, entry: StoreEntity | StoreCyberObservable) => {
  const fullUrl = `${url + resolveLink(entry.entity_type)}/${entry.internal_id}`;
  const author = entry.createdBy?.name ?? 'Unknown';
  return `
        <p style="padding:0; margin:0; line-height:140%; font-size:18px;">
            <a style="color:#f507bc8; text-decoration:none;" href="${fullUrl}">New <i>${entry.entity_type}</i> entity</a>
        </p>
        <p style="color: #999999; margin: 0;">By ${author}, ${prepareDate(entry.created_at)}</p>
        <table cellpadding="0" cellspacing="0" style="width: 100%; border-collapse:collapse; margin-top: 10pt; font-size: 10pt;">
            <tr>
                <td bgcolor="#ffffff" style="padding:0; width: 100%; text-align:center; background:#ffffff; background-color:#ffffff;" valign="top">
                    <strong>${defaultValue(entry)}</strong>
                </td>
            </tr>
            <tr>
                <td bgcolor="#ffffff" style="padding:0; width: 100%; text-align:center; background:#ffffff; background-color:#ffffff;" valign="top">
                    ${truncate(entityDescription(entry), 60)}
                </td>
            </tr>
        </table>
        <hr style="margin:15pt 0 10pt 0; color: #f6f6f6; border-top: #f6f6f6 1px solid; background: #f6f6f6">
  `;
};

export const technicalRelationToHtml = (url: string, entry: StoreRelation) => {
  const fullUrl = `${url + resolveLink(entry.to.entity_type)}/${entry.to.internal_id}/knowledge/relations/${entry.internal_id}`;
  const author = entry.createdBy?.name ?? 'Unknown';
  return `
            <tr>
                <td bgcolor="#ffffff" style="padding:0; width: 40%; text-align:left; background: #ffffff;background-color:#ffffff;" valign="top">
                    <a style="color:#f507bc8; text-decoration:none;" href="${fullUrl}">${truncate(defaultValue(entry.from), 80)}.</a>
                </td>
                <td bgcolor="#ffffff" style="padding:0; width: 30%; text-align:left; background: #ffffff;background-color:#ffffff;" valign="top">
                    ${truncate(defaultValue(entry.from), 60)}
                </td>
                <td bgcolor="#ffffff" style="padding:0; width: 30%; text-align:left; background: #ffffff;background-color: #ffffff;" valign="top">
                    <span style="color: #999999; margin: 0;">By ${author}, ${prepareDate(entry.created_at)}</span>
                 </td>
            </tr>
  `;
};
