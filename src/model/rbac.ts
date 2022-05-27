import { Util } from "../util";

export interface Role {
    id: string;
    name: string;
    rightIds?: string[];
    [key: string]: any;
}

export interface Right {
    id: string;
    name: string;


}

/**
 * system default Role and Rights
 */
export class RBACDefault {

    //system defined default rights
    /**
     * @summary system defined right ids
     */
    static systemRightIds = ['Admin', 'Reporter', 'User'];
    static rightAdmin: Right = { id: 'Admin', name: 'Admin', };
    static rightReporter: Right = { id: 'Reporter', name: 'Reporter' };
    static rightUser: Right = { id: 'User', name: 'User' };



    // new rights here
    static rightIds: string[] = [];


    ////  system defined roles
    /**
     * @summary system defined role ids
     */
    static systemRoleIds = ['Admin', 'Reporter', 'User'];
    static roleAdmin: Role = { id: 'Admin', name: 'Admin', rightIds: [this.rightAdmin.id] };
    static roleReporter: Role = { id: 'Reporter', name: 'Reporter', rightIds: [this.rightReporter.id] };
    static roleUser: Role = { id: 'User', name: 'User', rightIds: [this.rightUser.id] };


    static convert2RightList(rbac: RBAC, roleIds?: string[]) {
        if (!roleIds) return [];
        const distinctList = new Set();
        const roles = rbac.roles.filter(x => roleIds.includes(x.id));
        roles.forEach(y => {
            y.rightIds?.forEach(a => distinctList.add(a));
        })
        const rights: Right[] = [];
        distinctList.forEach(x => {
            const right = rbac.rights.find(y => y.id == x);
            if (right)
                rights.push(right);
        })
        return Util.clone(rights) as Right[];
    }

    static convert2RoleList(rbac: RBAC, roleIds?: string[]) {
        if (!roleIds) return [];
        const rbacCloned = Util.clone(rbac) as RBAC;
        const roles = rbacCloned.roles.filter(x => roleIds.includes(x.id));
        roles.forEach(y => {
            y.rights = rbacCloned.rights.filter(x => y.rightIds?.includes(x.id));
        })
        return roles;
    }

}

/**
 * Roles, Rights and relation between them
 */
export interface RBAC {
    roles: Role[];
    rights: Right[];
}



