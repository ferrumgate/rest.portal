
export interface FqdnIntelligenceSource {
    id: string;
    type: 'brightcloud.com' | string;
    name: string;
    insertDate: string;
    updateDate: string;
    [key: string]: any;
}

export interface FqdnIntelligenceCategory {
    id: string;
    name: string;
    isVisible: boolean;
}





export interface FqdnIntelligence {

    //intelligence sources
    sources: FqdnIntelligenceSource[];
    lists: FqdnIntelligenceList[];

}

export interface FqdnIntelligenceList {
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

export interface FqdnIntelligenceListStatus {
    id: string;
    lastCheck?: string;
    lastError?: string;
    hash?: string;
    isChanged?: boolean;
    hasFile?: boolean;
}

export interface FqdnIntelligenceListFiles {
    [key: string]: { page: number, hash: string };
}

/**
 * shows a list item
 */
export interface FqdnIntelligenceListItem {

    // list id
    id: string;
    page: number;
    // value
    fqdn: string;
    insertDate: string;
}




export interface FqdnIntelligenceItem {
    categoryId: string;
}




export function cloneFqdnIntelligenceList(obj: FqdnIntelligenceList): FqdnIntelligenceList {
    let item: FqdnIntelligenceList = {
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

export function cloneFqdnIntelligenceSource(obj: FqdnIntelligenceSource): FqdnIntelligenceSource {
    return {
        id: obj.id, insertDate: obj.insertDate, updateDate: obj.updateDate, name: obj.name, type: obj.type,
        apiKey: obj.apiKey
    }
}


export const fqdnCategories: FqdnIntelligenceCategory[] = [
    {
        id: 'w9FTQWw5e56Txcld',
        name: "Unknown",
        isVisible: true,
    },
    {
        id: 'cAhXVPaFm1NVSJxF',
        name: "BlackList",
        isVisible: false,
    },
    {
        id: 'hx396d3DptCY1rCq',
        name: "WhiteList",
        isVisible: false
    },
];

export const fqdnCategoriesMap = new Map<string, FqdnIntelligenceCategory>(fqdnCategories.map(obj => {
    return [obj.id, obj];
}),)
