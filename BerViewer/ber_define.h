#ifndef BER_DEFINE_H
#define BER_DEFINE_H

enum {
    DATA_STRING,
    DATA_HEX,
    DATA_BASE64,
    DATA_URL
};

enum {
    ENC_ENCRYPT,
    ENC_DECRYPT
};

enum {
    SIGN_SIGNATURE,
    SIGN_VERIFY
};

#endif // BER_DEFINE_H
