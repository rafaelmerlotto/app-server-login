import { generateKeyPairSync } from "crypto";
import { prisma } from "./prisma";



export interface JwtKeys {
    privateKey: string;
    publicKey: string;
}

function generateKeys(): JwtKeys {
    const keys = generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        },
    });
    return keys;
}

export async function getJwtKeys(): Promise<JwtKeys> {
    let keys = await prisma.jwtKey.findFirst();
    if (!keys) {
        const genKeys = generateKeys();
        keys = await prisma.jwtKey.create({
            data: {
                publicKey: genKeys.publicKey,
                privateKey: genKeys.privateKey
            },
        });
    };
    return {
        privateKey: keys.privateKey,
        publicKey: keys.publicKey
    }
}