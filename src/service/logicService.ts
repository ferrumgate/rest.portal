import { ErrorCodes, ErrorCodesInternal, RestfullException } from "../restfullException";
import { User } from "../model/user";
import { ConfigService } from "./configService";
import { Util } from "../util";
import { RBACDefault } from "../model/rbac";

export class LogicService {

    static async checkUserToUpdate(userId: string, input: User, configService: ConfigService) {


        const userDb = await configService.getUserById(userId);
        if (!userDb) throw new RestfullException(401, ErrorCodes.ErrNotAuthorized, ErrorCodesInternal.ErrUserNotFound, 'no user');

        //only set name. isLocked, is2FA, roleIds, groupIds, apikey and certificate
        let isChanged = false;
        if (!Util.isUndefinedOrNull(input.name) && userDb.name != input.name) {
            isChanged = true;
            userDb.name = input.name;
        }
        if (input.labels) {
            if (!Util.isArrayEqual(input.labels, userDb.labels))
                isChanged = true;
            userDb.labels = input.labels;
        }
        if (!Util.isUndefinedOrNull(input.is2FA)) {

            if (!input.is2FA) {//only user can set false
                if (input.is2FA != userDb.is2FA)
                    isChanged = true;
                userDb.is2FA = input.is2FA;
            }
        }
        if (!Util.isUndefinedOrNull(input.isLocked)) {
            if (input.isLocked != userDb.isLocked)
                isChanged = true;
            userDb.isLocked = input.isLocked;
        }
        if (input.roleIds) {
            //security, check input roles are system defined roles
            const filterRoles = input.roleIds.filter(x => RBACDefault.systemRoleIds.includes(x))
            if (!Util.isArrayEqual(userDb.roleIds, filterRoles))
                isChanged = true;
            userDb.roleIds = filterRoles;
        }
        const groups = await configService.getGroupsAll();
        if (input.groupIds) {
            const filteredGroups = input.groupIds.filter(x => groups.find(y => y.id == x));
            if (!Util.isArrayEqual(filteredGroups, userDb.groupIds))
                isChanged = true;
            userDb.groupIds = filteredGroups;
        }
        return {
            isChanged,
            userDb
        }

    }
}