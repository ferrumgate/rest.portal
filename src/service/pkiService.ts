import { ConfigService } from "./configService";
import * as pvtsutils from "pvtsutils";
import * as pkijs from 'pkijs';
import * as asn1js from "asn1js";
import peculiarCrypto from "@peculiar/webcrypto"

import * as ipaddr from 'ip-address';
import { isIPv4 } from "net";

///
///openssl  x509 -in downloaded.cert -inform PEM -text
///
type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';
type SignAlgorithm = "RSASSA-PKCS1-v1_5" | 'RSA-PSS' | 'ECDSA';

export interface CertificateRequest {
    hashAlg: HashAlgorithm;
    signAlg: SignAlgorithm;
    country: string,
    common: string;
    notBefore: Date,
    notAfter: Date,
    serial: number;
    isCA: boolean;
    sans: { type: 'email' | 'domain' | 'ip', value: string }[],
    ca?: {
        certificate: string,
        privateKey: string,
        hashAlg: HashAlgorithm;
        signAlg: SignAlgorithm;
    };

}


export class PKIService {
    /**
     *
     */
    static isInitted = false;
    constructor(protected configService: ConfigService) {
        if (!PKIService.isInitted)
            PKIService.init();
    }

    static init() {
        const webcrypto = new peculiarCrypto.Crypto();
        const name = "newEngine";
        pkijs.setEngine(name, new pkijs.CryptoEngine({ name, crypto: webcrypto }));
        PKIService.isInitted = true;
    }

    static toPEM(buffer: BufferSource, tag: string | 'CERTIFICATE' | 'PRIVATE KEY'): string {
        return [
            `-----BEGIN ${tag}-----`,
            PKIService.formatPEM(pvtsutils.Convert.ToBase64(buffer)),
            `-----END ${tag}-----`,
            "",
        ].join("\n");
    }

    static fromPEM(pem: string): ArrayBuffer {
        const base64 = pem
            .replace(/-{5}(BEGIN|END) .*-{5}/gm, "")
            .replace(/\s/gm, "");
        return pvtsutils.Convert.FromBase64(base64);
    }

    /**
     * Format string in order to have each line with length equal to 64
     * @param pemString String to format
     * @returns Formatted string
     */
    static formatPEM(pemString: string): string {
        const PEM_STRING_LENGTH = pemString.length, LINE_LENGTH = 64;
        const wrapNeeded = PEM_STRING_LENGTH > LINE_LENGTH;

        if (wrapNeeded) {
            let formattedString = "", wrapIndex = 0;

            for (let i = LINE_LENGTH; i < PEM_STRING_LENGTH; i += LINE_LENGTH) {
                formattedString += pemString.substring(wrapIndex, i) + "\r\n";
                wrapIndex = i;
            }

            formattedString += pemString.substring(wrapIndex, PEM_STRING_LENGTH);
            return formattedString;
        }
        else {
            return pemString;
        }
    }



    hashAlg = "SHA-1";
    signAlg = "RSASSA-PKCS1-v1_5";
    static async createCertificate(req: CertificateRequest) {

        const caCertificate = req.ca ? (await this.parseCertificate(req.ca.certificate))[0] : null;
        const caPrivateKey = req.ca ? await this.parsePrivateKey(req.ca.privateKey, req.ca.hashAlg, req.ca.signAlg) : null;

        const certificate = new pkijs.Certificate();
        const crypto = pkijs.getCrypto(true);

        //#region Put a static values
        certificate.version = 2;
        certificate.serialNumber = new asn1js.Integer({ value: req.serial });
        if (caCertificate) {
            certificate.issuer.fromSchema(caCertificate.subject.toSchema())
        } else {
            certificate.issuer.typesAndValues.push(new pkijs.AttributeTypeAndValue({
                type: "2.5.4.6", // Country name
                value: new asn1js.PrintableString({ value: req.country })
            }));
            certificate.issuer.typesAndValues.push(new pkijs.AttributeTypeAndValue({
                type: "2.5.4.3", // Common name
                value: new asn1js.BmpString({ value: req.common })
            }));
        }

        certificate.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
            type: "2.5.4.6", // Country name
            value: new asn1js.PrintableString({ value: req.country })
        }));
        certificate.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3", // Common name
            value: new asn1js.BmpString({ value: req.common })
        }));



        certificate.notBefore.value = req.notBefore
        certificate.notAfter.value = req.notAfter
        //certificate.notAfter.value.setFullYear(certificate.notAfter.value.getFullYear() + 1);

        certificate.extensions = []; // Extensions are not a part of certificate by default, it's an optional array

        //#region "BasicConstraints" extension
        const basicConstr = new pkijs.BasicConstraints({
            cA: req.isCA,
            pathLenConstraint: 3
        });

        certificate.extensions.push(new pkijs.Extension({
            extnID: "2.5.29.19",
            critical: true,
            extnValue: basicConstr.toSchema().toBER(false),
            parsedValue: basicConstr // Parsed value for well-known extensions
        }));
        //#endregion

        //#region "KeyUsage" extension
        const bitArray = new ArrayBuffer(1);
        const bitView = new Uint8Array(bitArray);

        bitView[0] |= 0x02; // Key usage "cRLSign" flag
        bitView[0] |= 0x04; // Key usage "keyCertSign" flag

        const keyUsage = new asn1js.BitString({ valueHex: bitArray });

        certificate.extensions.push(new pkijs.Extension({
            extnID: "2.5.29.15",
            critical: false,
            extnValue: keyUsage.toBER(false),
            parsedValue: keyUsage // Parsed value for well-known extensions
        }));
        //#endregion

        //#region "ExtendedKeyUsage" extension
        const extKeyUsage = new pkijs.ExtKeyUsage({
            keyPurposes: [
                "2.5.29.37.0",       // anyExtendedKeyUsage
                "1.3.6.1.5.5.7.3.1", // id-kp-serverAuth
                "1.3.6.1.5.5.7.3.2", // id-kp-clientAuth
                "1.3.6.1.5.5.7.3.3", // id-kp-codeSigning
                "1.3.6.1.5.5.7.3.4", // id-kp-emailProtection
                "1.3.6.1.5.5.7.3.8", // id-kp-timeStamping
                "1.3.6.1.5.5.7.3.9", // id-kp-OCSPSigning
                "1.3.6.1.4.1.311.10.3.1", // Microsoft Certificate Trust List signing
                "1.3.6.1.4.1.311.10.3.4"  // Microsoft Encrypted File System
            ]
        });

        certificate.extensions.push(new pkijs.Extension({
            extnID: "2.5.29.37",
            critical: false,
            extnValue: extKeyUsage.toSchema().toBER(false),
            parsedValue: extKeyUsage // Parsed value for well-known extensions
        }));

        //#region Microsoft-specific extensions
        const certType = new asn1js.Utf8String({ value: "certType" });

        certificate.extensions.push(new pkijs.Extension({
            extnID: "1.3.6.1.4.1.311.20.2",
            critical: false,
            extnValue: certType.toBER(false),
            parsedValue: certType // Parsed value for well-known extensions
        }));

        const prevHash = new asn1js.OctetString({ valueHex: (new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])).buffer });

        certificate.extensions.push(new pkijs.Extension({
            extnID: "1.3.6.1.4.1.311.21.2",
            critical: false,
            extnValue: prevHash.toBER(false),
            parsedValue: prevHash // Parsed value for well-known extensions
        }));

        const certificateTemplate = new pkijs.CertificateTemplate({
            templateID: "1.1.1.1.1.1",
            templateMajorVersion: 10,
            templateMinorVersion: 20
        });

        certificate.extensions.push(new pkijs.Extension({
            extnID: "1.3.6.1.4.1.311.21.7",
            critical: false,
            extnValue: certificateTemplate.toSchema().toBER(false),
            parsedValue: certificateTemplate // Parsed value for well-known extensions
        }));

        const caVersion = new pkijs.CAVersion({
            certificateIndex: 10,
            keyIndex: 20
        });

        certificate.extensions.push(new pkijs.Extension({
            extnID: "1.3.6.1.4.1.311.21.1",
            critical: false,
            extnValue: caVersion.toSchema().toBER(false),
            parsedValue: caVersion // Parsed value for well-known extensions
        }));

        ///domain names
        if (req.sans) {
            const altNames = new pkijs.GeneralNames({
                names: [

                ]
            });
            req.sans.forEach(x => {
                if (x.type == 'email') {
                    altNames.names.push(new pkijs.GeneralName({
                        type: 1, // rfc822Name
                        value: x.value
                    }))
                }
                if (x.type == 'domain') {
                    altNames.names.push(new pkijs.GeneralName({
                        type: 2, // dNSName
                        value: x.value
                    }))

                }
                if (x.type == 'ip') {
                    let ip = isIPv4(x.value) ? new ipaddr.Address4(x.value).toArray() : new ipaddr.Address6(x.value).toByteArray()
                    altNames.names.push(new pkijs.GeneralName({
                        type: 7, // iPAddress
                        value: new asn1js.OctetString({ valueHex: (new Uint8Array(ip)).buffer })
                    }))
                }
            })
            certificate.extensions.push(
                new pkijs.Extension({
                    extnID: "2.5.29.17",
                    critical: false,
                    extnValue: altNames.toSchema().toBER(false)
                }),
            )
        }
        //#endregion
        //#endregion

        //#region Create a new key pair
        //#region Get default algorithm parameters for key generation
        const algorithm = pkijs.getAlgorithmParameters(req.signAlg, "generateKey") as any;
        if ("hash" in algorithm.algorithm)
            algorithm.algorithm.hash.name = req.hashAlg;
        //#endregion

        const { privateKey, publicKey } = await crypto.generateKey(algorithm.algorithm, true, algorithm.usages) as Required<CryptoKeyPair>;
        //#endregion

        //#region Exporting public key into "subjectPublicKeyInfo" value of certificate
        await certificate.subjectPublicKeyInfo.importKey(publicKey);
        //#endregion

        //#region Signing final certificate
        if (!caCertificate || !caPrivateKey)
            await certificate.sign(privateKey, req.hashAlg);
        else {
            await certificate.sign(caPrivateKey, req.hashAlg);
        }
        //#endregion

        return {
            certificate,
            certificateBuffer: certificate.toSchema(true).toBER(false),
            privateKeyBuffer: await crypto.exportKey("pkcs8", privateKey),
        }
            ;
    }
    static async parsePrivateKey(content: string, hash: HashAlgorithm, sign: SignAlgorithm) {
        const crypto = pkijs.getCrypto(true);
        const buffer = (await PKIService.decodePEM(content))[0];
        return await crypto.importKey('pkcs8', { buffer: buffer, byteLength: buffer.byteLength, byteOffset: 0 }, { name: sign, hash: hash }, true, ["sign"])
    }


    static async decodePEM(pem: string, tag = "[A-Z0-9 ]+"): Promise<ArrayBuffer[]> {
        const pattern = new RegExp(`-{5}BEGIN ${tag}-{5}([a-zA-Z0-9=+\\/\\n\\r]+)-{5}END ${tag}-{5}`, "g");

        const res: ArrayBuffer[] = [];
        let matches: RegExpExecArray | null = null;
        // eslint-disable-next-line no-cond-assign
        while (matches = pattern.exec(pem)) {
            const base64 = matches[1]
                .replace(/\r/g, "")
                .replace(/\n/g, "");
            res.push(pvtsutils.Convert.FromBase64(base64));
        }

        return res;
    }
    static async parseSubject(pkcs10: pkijs.Certificate): Promise<any> {

        const typemap: Record<string, string> = {
            "2.5.4.6": "C",
            "2.5.4.11": "OU",
            "2.5.4.10": "O",
            "2.5.4.3": "CN",
            "2.5.4.7": "L",
            "2.5.4.8": "ST",
            "2.5.4.12": "T",
            "2.5.4.42": "GN",
            "2.5.4.43": "I",
            "2.5.4.4": "SN",
            "1.2.840.113549.1.9.1": "E-mail"
        };
        let subject: any = {};
        for (let i = 0; i < pkcs10.subject.typesAndValues.length; i++) {
            let typeval = typemap[pkcs10.subject.typesAndValues[i].type];
            if (typeof typeval === "undefined")
                typeval = pkcs10.subject.typesAndValues[i].type;

            const subjval = pkcs10.subject.typesAndValues[i].value.valueBlock.value;
            subject[typeval] = subjval;

        }
        return subject;
    }

    static async parseCertificate(content: string): Promise<pkijs.Certificate[]> {
        const source = (await this.decodePEM(content))[0];
        const buffers: ArrayBuffer[] = [];

        const buffer = pvtsutils.BufferSourceConverter.toArrayBuffer(source);
        const pem = pvtsutils.Convert.ToBinary(buffer);
        if (/----BEGIN CERTIFICATE-----/.test(pem)) {
            buffers.push(...await PKIService.decodePEM(pem, "CERTIFICATE"));
        } else {
            buffers.push(buffer);
        }

        const res: pkijs.Certificate[] = [];
        for (const item of buffers) {
            res.push(pkijs.Certificate.fromBER(item));
        }

        return res;
    }

    static async verifyCertificate(content: string, intermediateCertificates: pkijs.Certificate[], trustedCertificates: pkijs.Certificate[], crls: pkijs.CertificateRevocationList[]) {
        const certificateBuffer = this.fromPEM(content);
        //#region Major activities
        //#region Initial check
        if (certificateBuffer.byteLength === 0)
            return { result: false };
        //#endregion

        //#region Decode existing CERT
        const certificate = pkijs.Certificate.fromBER(certificateBuffer);
        //#endregion

        //#region Create certificate's array (end-user certificate + intermediate certificates)
        const certificates = [];
        certificates.push(...intermediateCertificates);
        certificates.push(certificate);
        //#endregion

        //#region Make a copy of trusted certificates array
        const trustedCerts = [];
        trustedCerts.push(...trustedCertificates);
        //#endregion

        //#region Create new X.509 certificate chain object
        const certChainVerificationEngine = new pkijs.CertificateChainValidationEngine({
            trustedCerts,
            certs: certificates,
            crls,
        });
        //#endregion

        // Verify CERT
        return certChainVerificationEngine.verify();
        //#endregion
    }
}