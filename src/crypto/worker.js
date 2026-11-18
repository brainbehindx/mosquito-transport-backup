import { parentPort } from 'worker_threads';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const algorithm = 'aes-256-gcm';

const IV_LENGTH = 12;
const TAG_LENGTH = 16;

export function encrypt(data, password) {
    const iv = randomBytes(IV_LENGTH);

    const cipher = createCipheriv(algorithm, password, iv);

    return Buffer.concat([
        iv,
        cipher.update(data),
        cipher.final(),
        cipher.getAuthTag()
    ]);
}

export function decrypt(data, password) {
    const iv = data.subarray(0, IV_LENGTH);
    const tag = data.subarray(data.length - TAG_LENGTH);
    const encrypted = data.subarray(IV_LENGTH, data.length - TAG_LENGTH);

    const decipher = createDecipheriv(algorithm, password, iv);

    decipher.setAuthTag(tag);

    return Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
    ]);
}

if (parentPort)
    parentPort.on('message', ({ input, session }) => {
        try {
            const [encode, ...args] = input;
            const result = (encode ? encrypt : decrypt)(...args);
            parentPort.postMessage([result, session]);
        } catch (error) {
            parentPort.postMessage([undefined, session, { error: `${error}` }]);
        }
    });
