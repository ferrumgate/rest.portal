
export interface SSHCertificate {
    publicKey?: string;
    privateKey?: string;
}


export type SSLCertificateCategory = 'ca' | 'jwt' | 'web' | 'tls' | 'auth';

export interface SSLCertificate {
    idEx?: string;
    name: string;
    labels: string[];
    insertDate: string;
    updateDate: string;
    publicCrt?: string;
    privateKey?: string;
    isEnabled: boolean;
    parentId?: string;
    category?: SSLCertificateCategory;
    isSystem?: boolean;

}
export interface SSLCertificateEx extends SSLCertificate {
    id: string;
    isIntermediate?: boolean;

}





