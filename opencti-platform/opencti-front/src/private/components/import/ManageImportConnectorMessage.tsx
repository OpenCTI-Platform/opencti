import React, {FunctionComponent} from "react";
import {useFormatter} from "../../../components/i18n";
import useGranted, {TAXIIAPI_SETCSVMAPPERS} from "../../../utils/hooks/useGranted";
import { Link } from "react-router-dom";

interface ManageImportConnectorMessageProps {
    name: string;
}
export const ManageImportConnectorMessage: FunctionComponent<ManageImportConnectorMessageProps> = ({name}) => {
    //const { t } = useFormatter();
    const isCsvMapperUpdater = useGranted([TAXIIAPI_SETCSVMAPPERS]);
    switch (name) {
        case 'ImportCsv':
            return <div style={{paddingTop: 6}}>
                {'There are not any configurations set yet.'}
                <div style={{paddingTop: 6}}>
                    {
                        isCsvMapperUpdater ?
                            <Link to="/dashboard/data/processing/csv_mapper">Create a CSV Mapper configuration</Link>
                            :
                            'Please contact an administrator.'
                    }
                </div>
            </div>
        case undefined : //In case there isn't any connector selected
            return <></>
        default:
            return <></>
    }
}