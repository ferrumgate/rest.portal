/**
 * @summary Elastic Search setting
 */
export interface ESSetting {
    host?: string;
    user?: string;
    pass?: string;
    //delete old records, maximum days
    deleteOldRecordsMaxDays?: number;

}

