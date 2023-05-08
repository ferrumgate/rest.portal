
export interface LetsEncryptChallenge {
    key: string;
    value: string;
    type: 'http' | 'dns';
}
export interface LetsEncrypt {
    domain: string;
    updateTime: string;
    email: string;
    challengeType?: 'http' | 'dns';
    privateKey?: string;
    publicCrt?: string;
    chainCrt?: string;
    fullChainCrt?: string;
    challenge?: LetsEncryptChallenge;
    isEnabled?: boolean;
}