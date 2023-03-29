import { Country } from "./country";

export interface IpIntelligenceSource {
    id: string;
    type: 'ipdata.co' | 'ipapi.com' | 'ipify.org' | string;
    name: string;
    insertDate: string;
    updateDate: string;
    [key: string]: any;
}

export interface IpIntelligenceFilterCategory {
    proxy?: boolean,
    hosting?: boolean,
    crawler?: boolean,
}


export interface IpIntelligenceCountryList {
    items: Country[];
}

export interface IpIntelligence {

    //intelligence sources
    sources: IpIntelligenceSource[];
    lists: IpIntelligenceList[];

}

export interface IpIntelligenceList {
    id: string;
    name: string;
    http?: {
        url: string;
        checkFrequency: number;//minutes

    };
    file?: {
        source?: string;
        key?: string;

    };
    splitter?: string;
    splitterIndex?: number;
    labels?: string[];
    updateDate: string;
    insertDate: string;
}

export interface IpIntelligenceListStatus {
    id: string;
    lastCheck?: string;
    lastError?: string;
    hash?: string;
    isChanged?: boolean;
    hasFile?: boolean;
}

export interface IpIntelligenceListFiles {
    [key: string]: { page: number, hash: string };
}

/**
 * shows a list item
 */
export interface IpIntelligenceListItem {

    // list id
    id: string;
    page: number;
    // value
    network: string;
    insertDate: string;
}




export interface IpIntelligenceItem {
    ip: string;
    countryCode: string;
    countryName: string;
    isProxy: boolean;
    isHosting: boolean;
    isCrawler: boolean;
}


export function cloneIpIntelligenceList(obj: IpIntelligenceList): IpIntelligenceList {
    let item: IpIntelligenceList = {
        id: obj.id, insertDate: obj.insertDate, updateDate: obj.updateDate, name: obj.name, labels: obj.labels,
        splitter: obj.splitter, splitterIndex: obj.splitterIndex
    }
    if (obj.file)
        item.file = {
            source: obj.file.source
        }
    if (obj.http)
        item.http = {
            checkFrequency: obj.http.checkFrequency,
            url: obj.http.url
        }
    return item;
}

export function cloneIpIntelligenceSource(obj: IpIntelligenceSource): IpIntelligenceSource {
    return {
        id: obj.id, insertDate: obj.insertDate, updateDate: obj.updateDate, name: obj.name, type: obj.type,
        apiKey: obj.apiKey
    }
}
