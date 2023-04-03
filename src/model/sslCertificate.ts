export interface SSLCertificate {
    id: string;
    name: string;
    labels: string[];
    parentId?: string;
    insertDate: string;
    updateDate: string;
    publicCrt?: string;
    privateKey?: string;
    isCA?: boolean;
    isIntermediate?: boolean;
    isSystem?: boolean;
    category?: string | 'web' | 'tls';

}

