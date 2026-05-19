#include "cardvault.h"

void cardvault_health_check(VaultCard* card) {
    // Default
    card->security = SecurityUnknown;
    strncpy(card->health_title, "Unknown", sizeof(card->health_title) - 1);
    strncpy(card->health_body, "Card type not identified.", sizeof(card->health_body) - 1);

    switch(card->tech) {
    case CardTechMifareClassic:
    case CardTechMifareClassic4K:
        card->security = SecurityBroken;
        strncpy(card->health_title, "MIFARE Classic", sizeof(card->health_title) - 1);
        strncpy(card->health_body,
            "Crypto-1, cracked 2008. Clonable with cheap hardware. "
            "Common in hotels and gyms.", sizeof(card->health_body) - 1);
        break;

    case CardTechMifareUltralight:
    case CardTechMifareUltralightC:
        card->security = SecurityWeak;
        strncpy(card->health_title, "MIFARE Ultralight", sizeof(card->health_title) - 1);
        strncpy(card->health_body,
            "Base has no auth, UL-C adds 3DES. Used for transit tickets and event passes.",
            sizeof(card->health_body) - 1);
        break;

    case CardTechMifarePlus:
        card->security = SecurityStrong;
        strncpy(card->health_title, "MIFARE Plus", sizeof(card->health_title) - 1);
        strncpy(card->health_body,
            "AES-128 encryption. Much stronger than Classic.",
            sizeof(card->health_body) - 1);
        break;

    case CardTechMifareDESFire:
        card->security = SecurityStrong;
        strncpy(card->health_title, "MIFARE DESFire", sizeof(card->health_title) - 1);
        strncpy(card->health_body,
            "3DES/AES-128 with mutual auth. Corporate badges and high-security transit.",
            sizeof(card->health_body) - 1);
        break;

    case CardTechNTAG203:
    case CardTechNTAG213:
    case CardTechNTAG215:
    case CardTechNTAG216:
    case CardTechNTAGI2C:
        card->security = SecurityWeak;
        strncpy(card->health_title, "NTAG (NFC Forum)", sizeof(card->health_title) - 1);
        strncpy(card->health_body,
            "Designed for data sharing, not access control. "
            "Optional 32-bit password on 213/215/216.",
            sizeof(card->health_body) - 1);
        break;

    case CardTechEMV:
        card->security = SecurityStrong;
        strncpy(card->health_title, "EMV Contactless", sizeof(card->health_title) - 1);
        strncpy(card->health_body,
            "Bank card. RSA/ECC with dynamic transaction tokens. Cannot be cloned.",
            sizeof(card->health_body) - 1);
        break;

    case CardTechFelica:
    case CardTechFelicaLite:
        card->security = SecurityModerate;
        strncpy(card->health_title, "FeliCa", sizeof(card->health_title) - 1);
        strncpy(card->health_body,
            "Used in Suica, Pasmo, Octopus. Triple-DES with mutual auth.",
            sizeof(card->health_body) - 1);
        break;

    case CardTechISO14443B:
    case CardTechCalypso:
        card->security = SecurityModerate;
        strncpy(card->health_title, "ISO 14443-B", sizeof(card->health_title) - 1);
        strncpy(card->health_body,
            "Used in e-Passports, Calypso transit cards, government ID.",
            sizeof(card->health_body) - 1);
        break;

    case CardTechISO15693:
    case CardTechSLIX:
    case CardTechSLIX2:
    case CardTechST25TB:
        card->security = SecurityWeak;
        strncpy(card->health_title, "ISO 15693 Vicinity", sizeof(card->health_title) - 1);
        strncpy(card->health_body,
            "Long-range (~1m). Libraries, asset tracking, ski passes.",
            sizeof(card->health_body) - 1);
        break;

    case CardTechEM4100:
        card->security = SecurityBroken;
        strncpy(card->health_title, "EM4100 125kHz", sizeof(card->health_title) - 1);
        strncpy(card->health_body,
            "No encryption. Broadcast in the clear. Common in older offices.",
            sizeof(card->health_body) - 1);
        break;

    case CardTechHIDProx:
        card->security = SecurityBroken;
        strncpy(card->health_title, "HID Prox 125kHz", sizeof(card->health_title) - 1);
        strncpy(card->health_body,
            "No encryption. Long-range readers can capture from 30cm.",
            sizeof(card->health_body) - 1);
        break;

    case CardTechIndala:
    case CardTechAWID:
    case CardTechIoProx:
    case CardTechParadox:
    case CardTechViking:
    case CardTechRFID125Generic:
        card->security = SecurityBroken;
        strncpy(card->health_title, "125kHz Proximity", sizeof(card->health_title) - 1);
        strncpy(card->health_body,
            "Unencrypted 125kHz format. Trivially cloneable.",
            sizeof(card->health_body) - 1);
        break;

    default:
        break;
    }

    card->health_title[sizeof(card->health_title) - 1] = '\0';
    card->health_body[sizeof(card->health_body) - 1]   = '\0';
}

const char* security_label(SecurityRating r) {
    switch(r) {
    case SecurityBroken:   return "BROKEN";
    case SecurityWeak:     return "WEAK";
    case SecurityModerate: return "MODERATE";
    case SecurityStrong:   return "STRONG";
    default:               return "UNKNOWN";
    }
}

void security_bar(SecurityRating r, char* out, size_t len) {
    const char* bars[] = {"[.   ]", "[##  ]", "[### ]", "[####]", "[??? ]"};
    strncpy(out, bars[(int)r < 5 ? (int)r : 4], len - 1);
    out[len - 1] = '\0';
}

const char* emulation_label(EmulationLevel e) {
    switch(e) {
    case EmulationNone:    return "Not supported";
    case EmulationUIDOnly: return "UID only";
    case EmulationFull:    return "Full";
    default:               return "?";
    }
}
