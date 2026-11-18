import { createHash } from "crypto";
import { one_mb } from "../utils.js";
import { addTask } from "./thread.js";
import { decrypt, encrypt } from "./worker.js";

const HOT_MB = one_mb * .5;

export const encryptData = async (buf, password) => {
    if (buf.byteLength >= HOT_MB) {
        return Buffer.from(await addTask([true, buf, password]));
    }

    return encrypt(buf, password);
}

export const decryptData = async (buf, password) => {
    if (buf.byteLength >= HOT_MB) {
        return Buffer.from(await addTask([false, buf, password]));
    }

    return decrypt(buf, password);
}

export const hashPassword = (password) =>
    createHash('sha-256')
        .update(password)
        .digest('base64')
        .substring(0, 32);