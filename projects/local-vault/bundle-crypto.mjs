import crypto from "node:crypto";
import fs from "node:fs";

const MAGIC = Buffer.from("GMBX", "ascii");
const VERSION = 1;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = MAGIC.length + 1 + SALT_BYTES + IV_BYTES;

export const MAX_BUNDLE_BYTES = 100 * 1024 * 1024;
export const BUNDLE_CIPHER_OVERHEAD = HEADER_BYTES + TAG_BYTES;
export const MAX_ENCRYPTED_BUNDLE_BYTES = MAX_BUNDLE_BYTES + BUNDLE_CIPHER_OVERHEAD;

const SCRYPT_OPTIONS = { N: 32_768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

export function validateBundlePassphrase(value) {
  if (typeof value !== "string") {
    throw new Error("Enter a bundle passphrase.");
  }
  const passphrase = value.normalize("NFC");
  const characterCount = Array.from(passphrase).length;
  if (characterCount < 16 || characterCount > 256 || Buffer.byteLength(passphrase, "utf8") > 1024) {
    throw new Error("Bundle passphrases must be 16 to 256 characters.");
  }
  return passphrase;
}

function deriveBundleKey(passphrase, salt) {
  return crypto.scryptSync(validateBundlePassphrase(passphrase), salt, 32, SCRYPT_OPTIONS);
}

function writeAllSync(fd, buffer) {
  let offset = 0;
  while (offset < buffer.length) {
    const count = fs.writeSync(fd, buffer, offset, buffer.length - offset);
    if (count <= 0) throw new Error("Bundle file could not be written.");
    offset += count;
  }
}

function readExactSync(fd, buffer, position) {
  let offset = 0;
  while (offset < buffer.length) {
    const count = fs.readSync(fd, buffer, offset, buffer.length - offset, position + offset);
    if (count === 0) throw new Error("Bundle file ended unexpectedly.");
    offset += count;
  }
}

function openRegularFile(pathname, flags) {
  const info = fs.lstatSync(pathname);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error("Bundle must be a regular file.");
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  return fs.openSync(pathname, flags | noFollow);
}

export function encryptBundleFile(plaintextPath, encryptedPath, passphrase) {
  const inputFd = openRegularFile(plaintextPath, fs.constants.O_RDONLY);
  let outputFd;
  let outputCreated = false;
  let key;
  let input;
  try {
    const info = fs.fstatSync(inputFd);
    if (info.size < 1 || info.size > MAX_BUNDLE_BYTES) {
      throw new Error("Bundle must be between 1 byte and 100 MiB.");
    }
    const salt = crypto.randomBytes(SALT_BYTES);
    const iv = crypto.randomBytes(IV_BYTES);
    const header = Buffer.concat([MAGIC, Buffer.from([VERSION]), salt, iv]);
    key = deriveBundleKey(passphrase, salt);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    key.fill(0);
    key = undefined;
    cipher.setAAD(header);

    const createExclusive = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL;
    outputFd = fs.openSync(encryptedPath, createExclusive, 0o600);
    outputCreated = true;
    writeAllSync(outputFd, header);
    input = Buffer.alloc(64 * 1024);
    let position = 0;
    while (position < info.size) {
      const count = fs.readSync(inputFd, input, 0, Math.min(input.length, info.size - position), position);
      if (count === 0) throw new Error("Bundle file ended unexpectedly.");
      position += count;
      writeAllSync(outputFd, cipher.update(input.subarray(0, count)));
    }
    writeAllSync(outputFd, cipher.final());
    writeAllSync(outputFd, cipher.getAuthTag());
    fs.fsyncSync(outputFd);
    return info.size + BUNDLE_CIPHER_OVERHEAD;
  } catch (error) {
    if (outputCreated) {
      try { fs.unlinkSync(encryptedPath); } catch {}
    }
    throw error;
  } finally {
    key?.fill(0);
    input?.fill(0);
    try { fs.closeSync(inputFd); } catch {}
    if (outputFd !== undefined) {
      try { fs.closeSync(outputFd); } catch {}
    }
  }
}

export function decryptBundleFile(encryptedPath, plaintextPath, passphrase) {
  const inputFd = openRegularFile(encryptedPath, fs.constants.O_RDONLY);
  let outputFd;
  let outputCreated = false;
  let key;
  let input;
  try {
    const info = fs.fstatSync(inputFd);
    if (info.size <= BUNDLE_CIPHER_OVERHEAD || info.size > MAX_ENCRYPTED_BUNDLE_BYTES) {
      throw new Error("Encrypted bundle has an invalid size.");
    }
    const header = Buffer.alloc(HEADER_BYTES);
    readExactSync(inputFd, header, 0);
    if (!header.subarray(0, MAGIC.length).equals(MAGIC) || header[MAGIC.length] !== VERSION) {
      throw new Error("This is not a supported encrypted GitMesh bundle.");
    }
    const saltStart = MAGIC.length + 1;
    const salt = header.subarray(saltStart, saltStart + SALT_BYTES);
    const ivStart = saltStart + SALT_BYTES;
    const iv = header.subarray(ivStart, ivStart + IV_BYTES);
    const tag = Buffer.alloc(TAG_BYTES);
    readExactSync(inputFd, tag, info.size - TAG_BYTES);
    key = deriveBundleKey(passphrase, salt);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    key.fill(0);
    key = undefined;
    decipher.setAAD(header);
    decipher.setAuthTag(tag);

    const createExclusive = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL;
    outputFd = fs.openSync(plaintextPath, createExclusive, 0o600);
    outputCreated = true;
    input = Buffer.alloc(64 * 1024);
    let position = HEADER_BYTES;
    let remaining = info.size - BUNDLE_CIPHER_OVERHEAD;
    let plaintextBytes = 0;
    while (remaining > 0) {
      const requested = Math.min(input.length, remaining);
      const count = fs.readSync(inputFd, input, 0, requested, position);
      if (count === 0) throw new Error("Bundle file ended unexpectedly.");
      position += count;
      remaining -= count;
      const plaintext = decipher.update(input.subarray(0, count));
      plaintextBytes += plaintext.length;
      if (plaintextBytes > MAX_BUNDLE_BYTES) throw new Error("Decrypted bundle is too large.");
      try {
        writeAllSync(outputFd, plaintext);
      } finally {
        plaintext.fill(0);
      }
    }
    let finalBlock;
    try {
      finalBlock = decipher.final();
    } catch {
      throw new Error("Bundle authentication failed. Check the passphrase or verify the file is intact.");
    }
    plaintextBytes += finalBlock.length;
    if (plaintextBytes < 1 || plaintextBytes > MAX_BUNDLE_BYTES) {
      throw new Error("Decrypted bundle has an invalid size.");
    }
    try {
      writeAllSync(outputFd, finalBlock);
    } finally {
      finalBlock.fill(0);
    }
    fs.fsyncSync(outputFd);
    return plaintextBytes;
  } catch (error) {
    if (outputCreated) {
      try { fs.unlinkSync(plaintextPath); } catch {}
    }
    throw error;
  } finally {
    key?.fill(0);
    input?.fill(0);
    try { fs.closeSync(inputFd); } catch {}
    if (outputFd !== undefined) {
      try { fs.closeSync(outputFd); } catch {}
    }
  }
}

export function encryptBundleBuffer(plaintext, passphrase) {
  if (!Buffer.isBuffer(plaintext) || plaintext.length < 1 || plaintext.length > MAX_BUNDLE_BYTES) {
    throw new Error("Bundle must be between 1 byte and 100 MiB.");
  }
  const salt = crypto.randomBytes(SALT_BYTES);
  const iv = crypto.randomBytes(IV_BYTES);
  const header = Buffer.concat([MAGIC, Buffer.from([VERSION]), salt, iv]);
  const key = deriveBundleKey(passphrase, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  key.fill(0);
  cipher.setAAD(header);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([header, ciphertext, cipher.getAuthTag()]);
}

export function decryptBundleBuffer(encrypted, passphrase) {
  if (!Buffer.isBuffer(encrypted) ||
      encrypted.length <= BUNDLE_CIPHER_OVERHEAD ||
      encrypted.length > MAX_ENCRYPTED_BUNDLE_BYTES) {
    throw new Error("Encrypted bundle has an invalid size.");
  }
  if (!encrypted.subarray(0, MAGIC.length).equals(MAGIC) ||
      encrypted[MAGIC.length] !== VERSION) {
    throw new Error("This is not a supported encrypted GitMesh bundle.");
  }

  const header = encrypted.subarray(0, HEADER_BYTES);
  const saltStart = MAGIC.length + 1;
  const salt = encrypted.subarray(saltStart, saltStart + SALT_BYTES);
  const ivStart = saltStart + SALT_BYTES;
  const iv = encrypted.subarray(ivStart, ivStart + IV_BYTES);
  const ciphertext = encrypted.subarray(HEADER_BYTES, encrypted.length - TAG_BYTES);
  const tag = encrypted.subarray(encrypted.length - TAG_BYTES);

  let key;
  try {
    key = deriveBundleKey(passphrase, salt);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    key.fill(0);
    key = undefined;
    decipher.setAAD(header);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plaintext.length < 1 || plaintext.length > MAX_BUNDLE_BYTES) {
      throw new Error("Decrypted bundle has an invalid size.");
    }
    return plaintext;
  } catch {
    throw new Error("Bundle authentication failed. Check the passphrase or verify the file is intact.");
  } finally {
    key?.fill(0);
  }
}
