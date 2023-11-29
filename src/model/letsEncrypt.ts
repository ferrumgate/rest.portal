
export interface LetsEncryptChallenge {
    key: string;
    value: string;
    type: 'http' | 'dns';
}
export interface LetsEncrypt {
    domain: string;
    updateDate: string;
    email: string;
    challengeType?: 'http' | 'dns';
    privateKey?: string;
    publicCrt?: string;
    chainCrt?: string;
    fullChainCrt?: string;
    challenge?: LetsEncryptChallenge;
    isEnabled?: boolean;
}

export function cloneLetsEncrypt(val: LetsEncrypt): LetsEncrypt {
    return {
        domain: val.domain,
        updateDate: val.updateDate,
        email: val.email,
        challengeType: val.challengeType,
        privateKey: val.privateKey,
        publicCrt: val.publicCrt,
        fullChainCrt: val.fullChainCrt,
        chainCrt: val.chainCrt,
        challenge: val.challenge ? { ...val.challenge } : undefined,
        isEnabled: val.isEnabled

    }
}