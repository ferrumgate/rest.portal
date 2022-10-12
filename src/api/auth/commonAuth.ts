
import { HelperService } from "../../service/helperService";
import { BaseAuth } from "../../model/authSettings";
import { User } from "../../model/user";
import { RestfullException } from "../../restfullException";
import { ErrorCodes } from "../../restfullException";

/**
 * common user checking function
 * @param user 
 */
export async function checkUser(user?: User, baseAuth?: BaseAuth) {
    if (!user || !baseAuth)
        throw new RestfullException(401, ErrorCodes.ErrNotAuthenticated, "not authenticated");
    HelperService.isValidUser(user);
    HelperService.isFromSource(user, `${baseAuth.baseType}-${baseAuth.type}`);

}