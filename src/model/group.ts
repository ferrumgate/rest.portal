


export interface Group {
    id: string;
    name: string;
    labels: string[];
    isEnabled: boolean;
    insertDate: string;
    updateDate: string;
    //for example sync from active directory
    source?: string;

}

export function cloneGroup(grp: Group): Group {
    return {
        id: grp.id, labels: Array.from(grp.labels || []), name: grp.name, isEnabled: grp.isEnabled,
        updateDate: grp.updateDate, insertDate: grp.insertDate

    }
}