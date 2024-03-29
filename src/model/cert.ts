import { LetsEncrypt } from "./letsEncrypt";

export interface SSHCertificate {
    publicKey?: string;
    privateKey?: string;
}


export type SSLCertificateCategory = 'ca' | 'jwt' | 'web' | 'tls' | 'auth';

export interface SSLCertificateBase {
    publicCrt?: string;
    privateKey?: string;
    parentId?: string;
    category?: SSLCertificateCategory;
    letsEncrypt?: LetsEncrypt | null;
    chainCrt?: string;
}

export interface SSLCertificate extends SSLCertificateBase {
    idEx?: string;
    name: string;
    labels: string[];
    usages: string[];
    insertDate: string;
    updateDate: string;
    isEnabled: boolean;
    isSystem?: boolean;


}
export interface SSLCertificateEx extends SSLCertificate {
    id: string;

}

/**
 *  don't copy certificate public or private keys
 */
export function cloneSSlCertificate(obj: SSLCertificate): SSLCertificate {
    return {

        insertDate: obj.insertDate,
        updateDate: obj.updateDate,
        name: obj.name,
        category: obj.category,
        isEnabled: obj.isEnabled,
        labels: obj.labels ? Array.from(obj.labels) : [],
        usages: obj.usages ? Array.from(obj.usages) : [],
    }
}
//*  don't copy certificate public or private keys
export function cloneSSlCertificateEx(obj: SSLCertificateEx): SSLCertificateEx {
    return {
        ...cloneSSlCertificate(obj),
        id: obj.id
    }
}





