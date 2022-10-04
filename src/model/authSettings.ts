export interface BaseAuth {
    id: string;
    name: string;
    baseType: 'local' | 'oauth' | 'saml' | 'ldap';
    type: 'local' | 'google' | 'linkedin';
    tags?: string[];
}
export interface BaseOAuth extends BaseAuth {
    clientID: string,
    clientSecret: string,
}
export interface BaseLdap extends BaseAuth {

}
export interface BaseSaml extends BaseAuth {

}
export interface BaseLocal extends BaseAuth {

}



export interface AuthLocal extends BaseLocal {
    isForgotPassword?: number;
    isRegister?: number;
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

export interface AuthSettings {
    local: AuthLocal;
    oauth?: AuthOAuth;
    ldap?: AuthLdap;
    saml?: AuthSaml;
}