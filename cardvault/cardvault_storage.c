#include "cardvault.h"
#include <flipper_format/flipper_format.h>
#include <storage/storage.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight.h>

// Forward declarations
void cardvault_health_check(VaultCard* card);

#define CARDVAULT_DIR        "/ext/apps_data/cardvault"
#define CARDVAULT_CARDS_DIR  "/ext/apps_data/cardvault/cards"
#define CARDVAULT_FILETYPE   "CardVault Card"
#define CARDVAULT_VERSION    1

// ─── Sanitize card name for use as filename ───────────────────────────────────
static void name_to_filename(const char* name, char* out, size_t out_size) {
    size_t j = 0;
    for(size_t i = 0; name[i] && j < out_size - 6; i++) {
        char c = name[i];
        if((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_') {
            out[j++] = c;
        } else if(c == ' ') {
            out[j++] = '_';
        }
    }
    if(j == 0) { out[j++] = 'c'; out[j++] = 'a'; out[j++] = 'r'; out[j++] = 'd'; }
    strncpy(&out[j], ".cvc", 5);
    out[j + 4] = '\0';
}

static void card_filepath(const char* name, char* out, size_t out_size) {
    char fn[CARDVAULT_MAX_NAME + 8];
    name_to_filename(name, fn, sizeof(fn));
    snprintf(out, out_size, "%s/%s", CARDVAULT_CARDS_DIR, fn);
}

// ─── Ensure directories exist ─────────────────────────────────────────────────
static void ensure_dirs(Storage* storage) {
    storage_simply_mkdir(storage, CARDVAULT_DIR);
    storage_simply_mkdir(storage, CARDVAULT_CARDS_DIR);
}

// ─── Save one card to disk ────────────────────────────────────────────────────
bool cardvault_save_card(VaultCard* card) {
    if(!card->valid) return false;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    ensure_dirs(storage);

    char path[128];
    card_filepath(card->name, path, sizeof(path));

    FlipperFormat* ff = flipper_format_file_alloc(storage);
    bool ok = false;

    do {
        if(!flipper_format_file_open_new(ff, path)) break;
        if(!flipper_format_write_header_cstr(ff, CARDVAULT_FILETYPE, CARDVAULT_VERSION)) break;

        // ── Metadata ──────────────────────────────────────────────────────────
        if(!flipper_format_write_string_cstr(ff, "Name", card->name)) break;
        uint32_t folder = card->folder;
        if(!flipper_format_write_uint32(ff, "Folder", &folder, 1)) break;
        uint32_t tech = (uint32_t)card->tech;
        if(!flipper_format_write_uint32(ff, "Tech", &tech, 1)) break;
        uint32_t emu = (uint32_t)card->emu_level;
        if(!flipper_format_write_uint32(ff, "Emulation", &emu, 1)) break;
        uint32_t is_rfid = card->is_rfid ? 1 : 0;
        if(!flipper_format_write_uint32(ff, "IsRFID", &is_rfid, 1)) break;

        // ── UID ───────────────────────────────────────────────────────────────
        uint32_t uid_len = card->uid_len;
        if(!flipper_format_write_uint32(ff, "UID_Len", &uid_len, 1)) break;
        if(uid_len > 0) {
            if(!flipper_format_write_hex(ff, "UID", card->uid, uid_len)) break;
        }
        if(!flipper_format_write_hex(ff, "ATQA", card->atqa, 2)) break;
        uint32_t sak = card->sak;
        if(!flipper_format_write_uint32(ff, "SAK", &sak, 1)) break;

        // ── NTAG / Ultralight full page dump ──────────────────────────────────
        if(card->full_data && card->full_data_protocol == NfcProtocolMfUltralight) {
            MfUltralightData* mfu = (MfUltralightData*)card->full_data;
            uint32_t pages = mfu->pages_total;
            if(!flipper_format_write_uint32(ff, "MFU_Pages", &pages, 1)) break;
            bool pages_ok = true;
            for(uint16_t i = 0; i < pages && pages_ok; i++) {
                char key[16];
                snprintf(key, sizeof(key), "Page_%d", i);
                pages_ok = flipper_format_write_hex(ff, key, mfu->page[i].data, 4);
            }
            if(!pages_ok) break;
        }

        // ── EMV brand if present ──────────────────────────────────────────────
        if(card->tech == CardTechEMV && card->emv_pan[0]) {
            if(!flipper_format_write_string_cstr(ff, "EMV_Brand", card->emv_pan)) break;
        }

        ok = true;
    } while(false);

    flipper_format_free(ff);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

// ─── Load one card from disk ──────────────────────────────────────────────────
static bool load_card_from_file(const char* path, VaultCard* card) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    FlipperFormat* ff = flipper_format_file_alloc(storage);
    bool ok = false;

    memset(card, 0, sizeof(VaultCard));

    do {
        if(!flipper_format_file_open_existing(ff, path)) break;

        FuriString* filetype = furi_string_alloc();
        uint32_t version = 0;
        bool header_ok = flipper_format_read_header(ff, filetype, &version);
        bool type_ok = furi_string_equal_str(filetype, CARDVAULT_FILETYPE);
        furi_string_free(filetype);
        if(!header_ok || !type_ok) break;

        // ── Metadata ──────────────────────────────────────────────────────────
        FuriString* name_str = furi_string_alloc();
        if(!flipper_format_read_string(ff, "Name", name_str)) {
            furi_string_free(name_str);
            break;
        }
        strncpy(card->name, furi_string_get_cstr(name_str), CARDVAULT_MAX_NAME - 1);
        furi_string_free(name_str);

        uint32_t folder = 0;
        flipper_format_read_uint32(ff, "Folder", &folder, 1);
        card->folder = (uint8_t)(folder < 5 ? folder : 0);

        uint32_t tech = 0;
        flipper_format_read_uint32(ff, "Tech", &tech, 1);
        card->tech = (CardTech)tech;

        uint32_t emu = 0;
        flipper_format_read_uint32(ff, "Emulation", &emu, 1);
        card->emu_level = (EmulationLevel)emu;

        uint32_t is_rfid = 0;
        flipper_format_read_uint32(ff, "IsRFID", &is_rfid, 1);
        card->is_rfid = (is_rfid == 1);

        // ── UID ───────────────────────────────────────────────────────────────
        uint32_t uid_len = 0;
        flipper_format_read_uint32(ff, "UID_Len", &uid_len, 1);
        card->uid_len = (uint8_t)(uid_len <= 10 ? uid_len : 0);
        if(card->uid_len > 0) {
            flipper_format_read_hex(ff, "UID", card->uid, card->uid_len);
            // Build uid_str
            char* p = card->uid_str;
            size_t rem = sizeof(card->uid_str);
            for(uint8_t i = 0; i < card->uid_len && rem > 3; i++) {
                int w = snprintf(p, rem, "%02X", card->uid[i]);
                p += w; rem -= w;
                if(i < card->uid_len - 1 && rem > 1) { *p++ = ':'; rem--; }
            }
        }
        flipper_format_read_hex(ff, "ATQA", card->atqa, 2);
        uint32_t sak = 0;
        flipper_format_read_uint32(ff, "SAK", &sak, 1);
        card->sak = (uint8_t)sak;

        // ── NTAG page dump ────────────────────────────────────────────────────
        uint32_t pages = 0;
        if(flipper_format_read_uint32(ff, "MFU_Pages", &pages, 1) && pages > 0 && pages <= 231) {
            MfUltralightData* mfu = mf_ultralight_alloc();
            mfu->pages_total = (uint16_t)pages;
            mfu->pages_read  = (uint16_t)pages;
            bool pages_ok = true;
            for(uint16_t i = 0; i < pages && pages_ok; i++) {
                char key[16];
                snprintf(key, sizeof(key), "Page_%d", i);
                pages_ok = flipper_format_read_hex(ff, key, mfu->page[i].data, 4);
            }
            if(pages_ok) {
                card->full_data          = mfu;
                card->full_data_protocol = NfcProtocolMfUltralight;
                card->emu_level          = EmulationFull;
            } else {
                mf_ultralight_free(mfu);
            }
        }

        // ── EMV brand ─────────────────────────────────────────────────────────
        FuriString* emv_str = furi_string_alloc();
        if(flipper_format_read_string(ff, "EMV_Brand", emv_str)) {
            strncpy(card->emv_pan, furi_string_get_cstr(emv_str),
                    sizeof(card->emv_pan) - 1);
        }
        furi_string_free(emv_str);

        // Run health check to populate security fields
        cardvault_health_check(card);
        card->valid = true;
        ok = true;
    } while(false);

    flipper_format_free(ff);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

// ─── Load all cards from the cards directory on startup ───────────────────────
void cardvault_load_all(CardVaultApp* app) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    ensure_dirs(storage);

    File* dir = storage_file_alloc(storage);
    if(!storage_dir_open(dir, CARDVAULT_CARDS_DIR)) {
        storage_file_free(dir);
        furi_record_close(RECORD_STORAGE);
        return;
    }

    FileInfo fi;
    char fname[64];
    while(storage_dir_read(dir, &fi, fname, sizeof(fname))) {
        if(file_info_is_dir(&fi)) continue;
        // Only load .cvc files
        size_t flen = strlen(fname);
        if(flen < 5 || strcmp(&fname[flen - 4], ".cvc") != 0) continue;
        if(app->card_count >= CARDVAULT_MAX_CARDS) break;

        char path[128];
        snprintf(path, sizeof(path), "%s/%s", CARDVAULT_CARDS_DIR, fname);

        VaultCard* card = &app->cards[app->card_count];
        if(load_card_from_file(path, card)) {
            app->card_count++;
        }
    }

    storage_dir_close(dir);
    storage_file_free(dir);
    furi_record_close(RECORD_STORAGE);
}

// ─── Delete a card file from disk ─────────────────────────────────────────────
bool cardvault_delete_card(VaultCard* card) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    char path[128];
    card_filepath(card->name, path, sizeof(path));
    bool ok = storage_simply_remove(storage, path);
    furi_record_close(RECORD_STORAGE);
    return ok;
}
