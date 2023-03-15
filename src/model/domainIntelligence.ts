export interface DomainCategory {
    id: string;
    name: string;
    group: string;
    code: number;
}
export const DomainCategoryWhiteList: DomainCategory = {
    id: 'vPMUCcXt4x3asePO', name: 'WhiteList', group: 'WhiteList', code: 1

}
export const DomainCategoryBlackList: DomainCategory = {
    id: '9Wi3NtQmzJdYzgif', name: 'BlackList', group: 'BlackList', code: 1

}


export const DomainCategories: DomainCategory[] = [
    DomainCategoryBlackList,
    DomainCategoryWhiteList
]


export interface DomainIntelligenceSource {
    id: string;
    type: 'ferrumdeep.com' | string;
    name: string;
    insertDate: string;
    updateDate: string;
    [key: string]: any;
}


export interface DomainIntelligenceBWItem {
    fqdn: string;
    insertDate: string;
    description?: string;
}


export interface DomainIntelligenceBWSource {
    id: string;
    name: string;
    source: string;
    insertDate: string;
    isBlack: boolean;
}

export interface DomainIntelligenceBWSourceEx {
    id: string;
    lastExecute?: string;
    error?: string
    content?: string;
    status?: string;
    contentHash?: string;
}



export interface DomainIntelligenceCategoryList {
    items: DomainCategory[];
}

export interface DomainIntelligence {
    //intelligence sources
    sources: DomainIntelligenceSource[];
    blackList: DomainIntelligenceBWSource[];
    whiteList: DomainIntelligenceBWSource[];

}


export interface DomainIntelligenceItem {
    fqdn: string;
    categoryList: string;
    insertDate: string;
    sourceList: string;
    whyBlack: string;
    whyWhite: string;

}