import { parse } from 'path';
import { createCipheriv, createDecipheriv, createHash } from 'node:crypto';

export const one_mb = 1024 * 1024,
    one_gb = one_mb * 1024;

export const wait = (ms = 1000) =>
    new Promise(resolve => {
        setTimeout(resolve, ms);
    });

export const RESERVED_DB = ['admin', 'local', 'config'];

export const Validator = {
    OBJECT: (o) => {
        if (typeof o !== 'object' || o === null) return false;
        return Object.prototype.toString.call(o) === '[object Object]'
            && Object.getPrototypeOf(o) === Object.prototype;
    },
    HTTP: a =>
        typeof a === 'string' &&
        /^(http:\/\/)(localhost|(\d{1,3}\.){3}\d{1,3}|([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(:\d+)?(\/[^\s]*)?$/.test(a),
    HTTPS: a =>
        typeof a === 'string' &&
        /^(https:\/\/)(localhost|(\d{1,3}\.){3}\d{1,3}|([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(:\d+)?(\/[^\s]*)?$/.test(a),
    LINK: a => Validator.HTTP(a) || Validator.HTTPS(a)
};

export function isPath(value) {
    if (
        typeof value !== 'string' ||
        !value.trim() ||
        value.includes('\0')
    ) {
        return false;
    }

    try {
        const parsed = parse(value);

        return Boolean(parsed.root || parsed.dir || parsed.base);
    } catch {
        return false;
    }
}

export function isValidMongoURL(value) {
    if (typeof value !== 'string' || !value.trim()) {
        return false;
    }

    try {
        const url = new URL(value);

        return (
            (url.protocol === 'mongodb:' ||
                url.protocol === 'mongodb+srv:') &&
            Boolean(url.hostname)
        );
    } catch {
        return false;
    }
}

export function isValidDbName(name) {
    const maxLength = 64;
    const invalidChars = /[\/\\ "$\0]/;

    return typeof name === 'string' &&
        name.length > 0 &&
        name.length <= maxLength &&
        !invalidChars.test(name);
}

export function isValidColName(name) {
    const maxLength = 120;
    const invalidChars = /\0/;

    return typeof name === 'string' &&
        name.length > 0 &&
        name.length <= maxLength &&
        !invalidChars.test(name) &&
        !name.startsWith('system.') &&
        !RESERVED_DB.includes(name);
}

const algorithm = 'aes-256-cbc';
const CachedMap = {};
const cache_expiry = 60_000 * 60;

const hashPassword = password => {
    if (CachedMap[password]) return CachedMap[password][0];

    const result = [
        createHash('sha256').update(password).digest('base64').substring(0, 32),
        createHash('md5').update(password).digest('base64').substring(0, 16)
    ];

    return CachedMap[password] = [
        result,
        setTimeout(() => {
            delete CachedMap[password];
        }, cache_expiry)
    ];
};

// Encrypt function
export function encryptData(data, password) {
    const [key, iv] = hashPassword(password);
    const cipher = createCipheriv(algorithm, key, iv);
    return Buffer.concat([
        cipher.update(data),
        cipher.final()
    ]);
}

// Decrypt function
export function decryptData(data, password) {
    const [key, iv] = hashPassword(password);

    const decipher = createDecipheriv(algorithm, key, iv);
    return Buffer.concat([
        decipher.update(data),
        decipher.final()
    ]);
}