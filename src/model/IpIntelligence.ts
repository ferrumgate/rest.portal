import { Country } from "./country";

export interface IpIntelligenceSource {
    type: string;
    name: string;
    [key: string]: any;
}
export interface IpIntelligenceSources {
    items: IpIntelligenceSource[];
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
    //allowed country list
    countryList: IpIntelligenceCountryList,
    //filter category option
    filterCategory: IpIntelligenceFilterCategory,
    //intelligence sources
    sources: IpIntelligenceSources

}

