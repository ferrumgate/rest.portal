
export interface BaseAuthId {
    id: string;
}

export interface BaseAuth {

    name: string;
    baseType: 'local' | 'oauth' | 'saml' | 'ldap';
    type: 'local' | 'google' | 'linkedin' | 'activedirectory' | 'auth0' | 'azure';
    tags?: string[];

    isEnabled: boolean;
    insertDate: string;
    updateDate: string;

}
export interface BaseOAuth extends BaseAuthId, BaseAuth {
    clientId: string,
    clientSecret: string,
    //this is a security flag, be carefull
    saveNewUser?: boolean;
}
export interface BaseLdap extends BaseAuthId, BaseAuth {
    host: string,
    bindDN?: string,
    bindPass?: string;
    searchBase: string;
    searchFilter?: string;
    usernameField: string;
    groupnameField: string;
    allowedGroups?: [];
    //this is a security flag, be carefull
    saveNewUser?: boolean;


}
export interface BaseSaml extends BaseAuthId, BaseAuth {
    issuer: string;
    cert: string;
    fingerPrint?: string;
    loginUrl: string;
    nameField: string;
    usernameField: string;
    //this is a security flag, be carefull
    saveNewUser?: boolean;
}
export interface BaseLocal extends BaseAuth {
    isForgotPassword?: boolean;
    isRegister?: boolean;
}



export interface AuthLocal extends BaseLocal {

}



export interface AuthOAuth {
    providers: BaseOAuth[];
}
export interface AuthLdap {
    providers: BaseLdap[];
}
export interface AuthSaml {
    providers: BaseSaml[];
}
export interface AuthCommon {

}

export interface AuthSettings {
    common: AuthCommon;
    local: AuthLocal;
    oauth: AuthOAuth;
    ldap: AuthLdap;
    saml: AuthSaml;
}