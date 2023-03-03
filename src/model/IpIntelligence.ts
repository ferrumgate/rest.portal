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
export interface IpIntelligenceBWItem {
    id: string;
    val: string;
    insertDate: string;
    description?: string;
}
export function calculateIpIntelligenceBWItemId(net: string) {
    return net.replace(/\//g, '#');
}

export interface IpIntelligenceCountryList {
    items: Country[];
}

export interface IpIntelligence {

    whiteList: IpIntelligenceBWItem[],
    blackList: IpIntelligenceBWItem[],
    //intelligence sources
    sources: IpIntelligenceSource[];

}




export interface IpIntelligenceItem {
    ip: string;
    countryCode: string;
    countryName: string;
    isProxy: boolean;
    isHosting: boolean;
    isCrawler: boolean;
}