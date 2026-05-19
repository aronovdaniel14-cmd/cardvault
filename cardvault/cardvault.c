#include "cardvault.h"
#include <storage/storage.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight_poller_sync.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a.h>
#include <lfrfid/lfrfid_worker.h>

void cardvault_draw_callback(Canvas* canvas, void* ctx);
bool cardvault_save_card(VaultCard* card);
void cardvault_load_all(CardVaultApp* app);
bool cardvault_delete_card(VaultCard* card);
void cardvault_health_check(VaultCard* card);

static void uid_to_str(const uint8_t* uid, uint8_t len, char* out, size_t out_size) {
    char* p = out;
    size_t rem = out_size;
    for(uint8_t i = 0; i < len && rem > 3; i++) {
        int w = snprintf(p, rem, "%02X", uid[i]);
        p += w; rem -= w;
        if(i < len - 1 && rem > 1) { *p++ = ':'; rem--; }
    }
    *p = '\0';
}

// ─── Free a card's allocated full_data based on its protocol ─────────────────
static void free_card_data(VaultCard* card) {
    if(!card->full_data) return;
    if(card->full_data_protocol == NfcProtocolMfUltralight) {
        mf_ultralight_free((MfUltralightData*)card->full_data);
    } else {
        free(card->full_data);
    }
    card->full_data = NULL;
}

static CardTech protocol_to_tech(NfcProtocol proto) {
    switch(proto) {
    case NfcProtocolIso14443_3a:  return CardTechISO14443A;
    case NfcProtocolIso14443_3b:  return CardTechISO14443B;
    case NfcProtocolIso14443_4a:  return CardTechEMV;
    case NfcProtocolIso14443_4b:  return CardTechISO14443B;
    case NfcProtocolIso15693_3:   return CardTechISO15693;
    case NfcProtocolFelica:       return CardTechFelica;
    case NfcProtocolMfUltralight: return CardTechNTAG215;
    case NfcProtocolMfClassic:    return CardTechMifareClassic;
    case NfcProtocolMfPlus:       return CardTechMifarePlus;
    case NfcProtocolMfDesfire:    return CardTechMifareDESFire;
    case NfcProtocolSlix:         return CardTechSLIX;
    case NfcProtocolSt25tb:       return CardTechST25TB;
    // Fallback: if scanner detected SOMETHING but we don't have a specific
    // mapping, assume it's an ISO14443A variant rather than reporting Unknown
    default:                      return CardTechISO14443A;
    }
}

// Identify NTAG sub-type from MfUltralightData by inspecting capability container
// or page count. Page 3 byte 2 holds the memory size identifier.
static CardTech identify_ntag_subtype(const MfUltralightData* data) {
    if(!data) return CardTechMifareUltralight;
    // Number of pages tells us the exact type:
    // NTAG213 = 45 pages, NTAG215 = 135 pages, NTAG216 = 231 pages
    uint16_t pages = data->pages_total;
    if(pages == 45)        return CardTechNTAG213;
    if(pages == 135)       return CardTechNTAG215;
    if(pages == 231)       return CardTechNTAG216;
    if(pages == 41)        return CardTechNTAG203;
    if(pages == 16 || pages == 20) return CardTechMifareUltralight;
    return CardTechMifareUltralight;
}

// ─── Phase 2A: full MIFARE Ultralight read ───────────────────────────────────
static bool read_full_mfu(CardVaultApp* app) {
    MfUltralightData* data = mf_ultralight_alloc();
    if(!data) return false;

    MfUltralightError err = mf_ultralight_poller_sync_read_card(app->nfc, data, NULL);
    if(err != MfUltralightErrorNone) {
        mf_ultralight_free(data);
        return false;
    }

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    free_card_data(&app->pending);
    app->pending.full_data          = data;
    app->pending.full_data_protocol = NfcProtocolMfUltralight;
    app->pending.tech               = identify_ntag_subtype(data);
    app->pending.emu_level          = EmulationFull;

    // Copy UID/ATQA/SAK from the ultralight data's iso14443_3a parent
    const Iso14443_3aData* iso = data->iso14443_3a_data;
    if(iso) {
        app->pending.uid_len = iso->uid_len;
        memcpy(app->pending.uid, iso->uid, iso->uid_len);
        uid_to_str(app->pending.uid, app->pending.uid_len,
                   app->pending.uid_str, sizeof(app->pending.uid_str));
        app->pending.atqa[0] = iso->atqa[0];
        app->pending.atqa[1] = iso->atqa[1];
        app->pending.sak     = iso->sak;
    }
    furi_mutex_release(app->mutex);
    return true;
}

// ─── Phase 2B: EMV read (UID + try to grab PAN/expiry from PPSE) ─────────────
// EMV reading is complex — for v1 we just get the UID via the 14443-4a poller
// and mark the card as detected. PAN/expiry parsing requires APDU exchange that
// the public SDK doesn't fully expose for free-form use, so we store placeholders.
// EMV brand detection from UID prefix and randomization patterns.
// We do NOT extract PAN/expiry numbers — that data could be misused for skimming.
// Brand identification helps users tell their cards apart by sight.
static const char* infer_emv_brand(const uint8_t* uid, uint8_t uid_len) {
    if(uid_len == 0) return "EMV Card";
    // Most EMV cards use randomized 4-byte UIDs starting with 0x08
    // The other bytes don't reliably encode the brand. The most accurate
    // brand detection requires reading the AID via SELECT PPSE, which we
    // intentionally don't do. So we just label it as a generic EMV card.
    if(uid[0] == 0x08) return "EMV Bank Card";
    if(uid_len == 4)   return "EMV (random UID)";
    if(uid_len == 7)   return "EMV (static UID)";
    return "EMV Card";
}

static bool read_full_emv(CardVaultApp* app) {
    // For privacy and safety reasons, we do not extract or display the PAN
    // (card number) or expiry date. Showing those values would enable
    // skimming use cases that this app should not support.
    //
    // What we DO show: card category (e.g. "EMV Bank Card") inferred from
    // UID structure, so users can recognize their own saved cards.
    const char* brand = infer_emv_brand(app->pending.uid, app->pending.uid_len);
    strncpy(app->pending.emv_pan, brand, sizeof(app->pending.emv_pan) - 1);
    app->pending.emv_pan[sizeof(app->pending.emv_pan) - 1] = '\0';

    strncpy(app->pending.emv_expiry, "-", sizeof(app->pending.emv_expiry) - 1);
    app->pending.emv_expiry[sizeof(app->pending.emv_expiry) - 1] = '\0';

    app->pending.emu_level = EmulationUIDOnly;
    return true;
}

// ─── Phase 1 poller callback ──────────────────────────────────────────────────
static NfcCommand uid_poller_cb(NfcGenericEvent event, void* ctx) {
    CardVaultApp* app = ctx;
    UNUSED(event);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(!app->scan_done && app->poller) {
        const NfcDeviceData* data = nfc_poller_get_data(app->poller);
        if(data) {
            const uint8_t* raw = (const uint8_t*)data;
            uint8_t uid_len = raw[0];
            if(uid_len > 0 && uid_len <= 10) {
                app->pending.uid_len = uid_len;
                memcpy(app->pending.uid, &raw[1], uid_len);
                uid_to_str(app->pending.uid, uid_len,
                           app->pending.uid_str, sizeof(app->pending.uid_str));
                app->pending.atqa[0] = raw[11];
                app->pending.atqa[1] = raw[12];
                app->pending.sak     = raw[13];
                if(app->pending.tech == CardTechMifareClassic && app->pending.sak == 0x18)
                    app->pending.tech = CardTechMifareClassic4K;
                // Refine ISO14443A by SAK if we don't already have a specific subtype
                if(app->pending.tech == CardTechISO14443A) {
                    if(app->pending.sak == 0x08 || app->pending.sak == 0x88) app->pending.tech = CardTechMifareClassic;
                    else if(app->pending.sak == 0x18) app->pending.tech = CardTechMifareClassic4K;
                    else if(app->pending.sak == 0x00) app->pending.tech = CardTechMifareUltralight;
                    else if(app->pending.sak == 0x20) app->pending.tech = CardTechEMV;
                    else if(app->pending.sak == 0x28 || app->pending.sak == 0x38) app->pending.tech = CardTechMifarePlus;
                }
            }
        }
        app->pending.scan_rssi    = -60;
        app->pending.scanned_tick = furi_get_tick();
        app->pending.valid        = true;
        cardvault_health_check(&app->pending);
        app->scan_done    = true;
        app->scan_success = true;
    }
    furi_mutex_release(app->mutex);
    view_port_update(app->view_port);
    return NfcCommandStop;
}

// ─── Scanner callback ────────────────────────────────────────────────────────
static void nfc_scanner_callback(NfcScannerEvent event, void* ctx) {
    CardVaultApp* app = ctx;
    if(event.type != NfcScannerEventTypeDetected) return;
    if(event.data.protocol_num == 0) return;

    NfcProtocol proto = event.data.protocols[0];
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->pending.tech    = protocol_to_tech(proto);
    app->pending.is_rfid = false;
    if(app->poller) {
        nfc_poller_stop(app->poller);
        nfc_poller_free(app->poller);
    }
    app->poller = nfc_poller_alloc(app->nfc, proto);
    nfc_poller_start(app->poller, uid_poller_cb, app);
    furi_mutex_release(app->mutex);
}

// ─── NFC scan thread: scan → detect → UID → full read (if supported) ─────────
static int32_t nfc_scan_thread(void* ctx) {
    CardVaultApp* app = ctx;

    // Phase 1: scanner detects what protocol the card is
    NfcScanner* scanner = nfc_scanner_alloc(app->nfc);
    nfc_scanner_start(scanner, nfc_scanner_callback, app);
    while(app->nfc_active && !app->scan_done) furi_delay_ms(100);
    nfc_scanner_stop(scanner);
    nfc_scanner_free(scanner);

    // Stop the UID poller now so we can run protocol-specific reads
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(app->poller) {
        nfc_poller_stop(app->poller);
        nfc_poller_free(app->poller);
        app->poller = NULL;
    }
    CardTech detected = app->pending.tech;
    app->reading_full = true;
    furi_mutex_release(app->mutex);

    if(!app->nfc_active || !app->scan_success) {
        app->reading_full = false;
        return 0;
    }

    // Phase 2: full read based on card type
    bool full_ok = false;
    if(detected == CardTechNTAG213 || detected == CardTechNTAG215 ||
       detected == CardTechNTAG216 || detected == CardTechNTAG203 ||
       detected == CardTechMifareUltralight || detected == CardTechMifareUltralightC) {
        full_ok = read_full_mfu(app);
    } else if(detected == CardTechEMV) {
        full_ok = read_full_emv(app);
    }

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->reading_full = false;
    if(!full_ok && app->pending.emu_level == EmulationNone) {
        // No full read — but UID-only emulation works for many 14443A cards
        if(detected == CardTechMifareClassic || detected == CardTechMifareClassic4K ||
           detected == CardTechISO14443A) {
            app->pending.emu_level = EmulationUIDOnly;
        }
    }
    furi_mutex_release(app->mutex);
    return 0;
}

// ─── RFID 125kHz ──────────────────────────────────────────────────────────────
static void rfid_read_callback(LFRFIDWorkerReadResult result, ProtocolId proto, void* ctx) {
    CardVaultApp* app = ctx;
    if(result != LFRFIDWorkerReadDone) return;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(!app->scan_done) {
        VaultCard* p = &app->pending;
        memset(p, 0, sizeof(VaultCard));
        p->is_rfid    = true;
        p->emu_level  = EmulationNone;
        switch(proto) {
        case LFRFIDProtocolEM4100:    p->tech = CardTechEM4100;        break;
        case LFRFIDProtocolGProxII:   p->tech = CardTechHIDProx;       break;
        case LFRFIDProtocolIndala26:  p->tech = CardTechIndala;        break;
        case LFRFIDProtocolAwid:      p->tech = CardTechAWID;          break;
        case LFRFIDProtocolIOProxXSF: p->tech = CardTechIoProx;        break;
        case LFRFIDProtocolParadox:   p->tech = CardTechParadox;       break;
        case LFRFIDProtocolViking:    p->tech = CardTechViking;        break;
        default:                      p->tech = CardTechRFID125Generic; break;
        }
        ProtocolDict* dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
        size_t uid_size = protocol_dict_get_data_size(dict, proto);
        if(uid_size > sizeof(p->uid)) uid_size = sizeof(p->uid);
        protocol_dict_get_data(dict, proto, p->uid, uid_size);
        protocol_dict_free(dict);
        p->uid_len = (uint8_t)uid_size;
        uid_to_str(p->uid, p->uid_len, p->uid_str, sizeof(p->uid_str));
        p->scanned_tick = furi_get_tick();
        p->valid        = true;
        cardvault_health_check(p);
        app->scan_success = true;
        app->scan_done    = true;
    }
    furi_mutex_release(app->mutex);
    view_port_update(app->view_port);
}

static int32_t rfid_scan_thread(void* ctx) {
    CardVaultApp* app = ctx;
    ProtocolDict* dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
    LFRFIDWorker* worker = lfrfid_worker_alloc(dict);
    lfrfid_worker_start_thread(worker);
    lfrfid_worker_read_start(worker, LFRFIDWorkerReadTypeAuto, rfid_read_callback, app);
    while(app->nfc_active && !app->scan_done) furi_delay_ms(100);
    lfrfid_worker_stop(worker);
    lfrfid_worker_stop_thread(worker);
    lfrfid_worker_free(worker);
    protocol_dict_free(dict);
    return 0;
}

// ─── EMULATION ────────────────────────────────────────────────────────────────
// Minimal listener callback — we just keep the listener alive.
// For NTAG/Ultralight the listener handles NDEF reads automatically.
// For ISO14443-3a UID-only, the listener handles anti-collision automatically.
static NfcCommand emu_listener_cb(NfcGenericEvent event, void* ctx) {
    UNUSED(event);
    UNUSED(ctx);
    return NfcCommandContinue;
}

static FuriThread* emu_thread = NULL;

static int32_t emu_thread_fn(void* ctx) {
    CardVaultApp* app = ctx;
    if(app->last_used_idx >= app->card_count) return 0;
    VaultCard* c = &app->cards[app->last_used_idx];
    if(!c->valid || c->emu_level == EmulationNone) return 0;

    NfcProtocol emu_proto;
    const NfcDeviceData* emu_data = NULL;

    app->emu_device = nfc_device_alloc();
    if(!app->emu_device) return 0;

    if(c->emu_level == EmulationFull && c->full_data &&
       c->full_data_protocol == NfcProtocolMfUltralight) {
        // Full NTAG/Ultralight — listener will respond to all page reads
        // including NDEF records, so your URL tag will work completely
        emu_proto = NfcProtocolMfUltralight;
        nfc_device_set_data(app->emu_device, emu_proto,
                            (const NfcDeviceData*)c->full_data);
        emu_data = nfc_device_get_data(app->emu_device, emu_proto);
    } else {
        // UID-only: build a minimal Iso14443_3aData struct on the stack
        // Layout confirmed from SDK: uid_len(1), uid[10], atqa[2], sak(1)
        uint8_t iso_buf[14];
        memset(iso_buf, 0, sizeof(iso_buf));
        iso_buf[0] = c->uid_len;
        memcpy(&iso_buf[1], c->uid, c->uid_len);
        iso_buf[11] = c->atqa[0] ? c->atqa[0] : 0x44;  // default NTAG ATQA
        iso_buf[12] = c->atqa[1];
        iso_buf[13] = c->sak;   // 0x00 for UL/NTAG, 0x08 for Classic

        emu_proto = NfcProtocolIso14443_3a;
        nfc_device_set_data(app->emu_device, emu_proto, (const NfcDeviceData*)iso_buf);
        emu_data = nfc_device_get_data(app->emu_device, emu_proto);
    }

    if(!emu_data) {
        nfc_device_free(app->emu_device);
        app->emu_device = NULL;
        return 0;
    }

    app->listener = nfc_listener_alloc(app->nfc, emu_proto, emu_data);
    nfc_listener_start(app->listener, emu_listener_cb, app);

    while(app->emu_active) furi_delay_ms(50);

    nfc_listener_stop(app->listener);
    nfc_listener_free(app->listener);
    app->listener = NULL;
    nfc_device_free(app->emu_device);
    app->emu_device = NULL;
    return 0;
}

static void start_emulation(CardVaultApp* app) {
    if(app->last_used_idx >= app->card_count) return;
    VaultCard* c = &app->cards[app->last_used_idx];
    if(!c->valid || c->emu_level == EmulationNone) return;
    app->emu_active = true;
    if(emu_thread) {
        furi_thread_join(emu_thread);
        furi_thread_free(emu_thread);
    }
    emu_thread = furi_thread_alloc_ex("CVEmu", 2048, emu_thread_fn, app);
    furi_thread_start(emu_thread);
}

static void stop_emulation(CardVaultApp* app) {
    app->emu_active = false;
    if(emu_thread) {
        furi_thread_join(emu_thread);
        furi_thread_free(emu_thread);
        emu_thread = NULL;
    }
}

// ─── Scan control ─────────────────────────────────────────────────────────────
static void start_scan(CardVaultApp* app) {
    free_card_data(&app->pending);
    memset(&app->pending, 0, sizeof(VaultCard));
    app->scan_done    = false;
    app->scan_success = false;
    app->reading_full = false;
    app->nfc_active   = true;
    if(app->scan_thread) {
        furi_thread_join(app->scan_thread);
        furi_thread_free(app->scan_thread);
        app->scan_thread = NULL;
    }
    app->scan_thread = furi_thread_alloc_ex(
        app->scan_mode == ScanModeNFC ? "CVNfc" : "CVRfid",
        2048,
        app->scan_mode == ScanModeNFC ? nfc_scan_thread : rfid_scan_thread,
        app);
    furi_thread_start(app->scan_thread);
}

static void stop_scan(CardVaultApp* app) {
    app->nfc_active = false;
    if(app->scan_thread) {
        furi_thread_join(app->scan_thread);
        furi_thread_free(app->scan_thread);
        app->scan_thread = NULL;
    }
}

static void save_pending(CardVaultApp* app) {
    if(app->card_count >= CARDVAULT_MAX_CARDS) return;
    VaultCard* c = &app->cards[app->card_count++];
    // Shallow copy then transfer ownership of full_data
    memcpy(c, &app->pending, sizeof(VaultCard));
    // Pending no longer owns the pointer
    app->pending.full_data = NULL;
    strncpy(c->name, app->name_buf, CARDVAULT_MAX_NAME - 1);
    c->name[CARDVAULT_MAX_NAME - 1] = '\0';
    c->folder = app->menu_sel;
    c->valid  = true;
    app->last_used_idx = app->card_count - 1;
}

static void discard_pending(CardVaultApp* app) {
    free_card_data(&app->pending);
    memset(&app->pending, 0, sizeof(VaultCard));
}

static void input_callback(InputEvent* event, void* ctx) {
    furi_message_queue_put(((CardVaultApp*)ctx)->event_queue, event, 0);
}

// ─── Input handler ───────────────────────────────────────────────────────────
static void handle_input(CardVaultApp* app, InputEvent* e) {
    if(e->type != InputTypeShort && e->type != InputTypeLong) return;
    furi_mutex_acquire(app->mutex, FuriWaitForever);

    switch(app->scene) {
    case SceneHome:
        if(e->key == InputKeyBack && e->type == InputTypeLong) { app->running = false; break; }
        if(e->key == InputKeyLeft  && app->folder_sel > 0) app->folder_sel--;
        if(e->key == InputKeyRight && app->folder_sel < 4) app->folder_sel++;
        if(e->key == InputKeyOk) { app->card_sel = 0; app->scene = SceneFolderView; }
        if(e->key == InputKeyDown) {
            app->prev_scene = SceneHome;
            app->scene = SceneScan;
            furi_mutex_release(app->mutex);
            start_scan(app);
            return;
        }
        break;

    case SceneFolderView: {
        uint8_t count = 0;
        for(uint8_t i = 0; i < app->card_count; i++)
            if(app->cards[i].valid && app->cards[i].folder == app->folder_sel) count++;
        if(e->key == InputKeyBack) { app->scene = SceneHome; break; }
        if(e->key == InputKeyUp   && app->card_sel > 0) app->card_sel--;
        if(e->key == InputKeyDown && app->card_sel + 1 < count) app->card_sel++;
        if(e->key == InputKeyOk  && count > 0) app->scene = SceneCardDetail;
        break;
    }

    case SceneCardDetail:
        if(e->key == InputKeyBack) { app->scene = SceneFolderView; break; }
        if(e->key == InputKeyOk) {
            uint8_t n = 0;
            for(uint8_t i = 0; i < app->card_count; i++) {
                if(app->cards[i].valid && app->cards[i].folder == app->folder_sel) {
                    if(n == app->card_sel) {
                        app->last_used_idx = i;
                        app->cards[i].last_used_tick = furi_get_tick();
                        break;
                    }
                    n++;
                }
            }
            VaultCard* sel = &app->cards[app->last_used_idx];
            if(sel->emu_level != EmulationNone) {
                app->scene = SceneEmulating;
                furi_mutex_release(app->mutex);
                start_emulation(app);
                return;
            }
        }
        if(e->key == InputKeyUp) app->scene = SceneHealthCheck;
        if(e->key == InputKeyDown) {
            // Delete card
            uint8_t n = 0;
            for(uint8_t i = 0; i < app->card_count; i++) {
                if(app->cards[i].valid && app->cards[i].folder == app->folder_sel) {
                    if(n == app->card_sel) {
                        cardvault_delete_card(&app->cards[i]);
                        free_card_data(&app->cards[i]);
                        // Shift remaining cards down
                        memmove(&app->cards[i], &app->cards[i + 1],
                                (app->card_count - i - 1) * sizeof(VaultCard));
                        app->card_count--;
                        if(app->card_sel > 0) app->card_sel--;
                        app->scene = SceneFolderView;
                        break;
                    }
                    n++;
                }
            }
        }
        break;

    case SceneEmulating:
        if(e->key == InputKeyBack || e->key == InputKeyOk) {
            furi_mutex_release(app->mutex);
            stop_emulation(app);
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->scene = SceneCardDetail;
        }
        break;

    case SceneScan:
        if(e->key == InputKeyBack) {
            furi_mutex_release(app->mutex);
            stop_scan(app);
            discard_pending(app);
            app->scene = app->prev_scene;
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            break;
        }
        if(!app->scan_done && (e->key == InputKeyLeft || e->key == InputKeyRight)) {
            ScanMode new_mode = (app->scan_mode == ScanModeNFC) ? ScanModeRFID : ScanModeNFC;
            furi_mutex_release(app->mutex);
            stop_scan(app);
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->scan_mode = new_mode;
            furi_mutex_release(app->mutex);
            start_scan(app);
            return;
        }
        // Don't advance until full read is done
        if(e->key == InputKeyOk && app->scan_done && app->scan_success && !app->reading_full) {
            memset(app->name_buf, 0, sizeof(app->name_buf));
            app->scene = SceneNameInput;
        }
        break;

    case SceneNameInput:
        // Back goes to a confirm-discard screen (FIX for "can't leave name screen")
        if(e->key == InputKeyBack) {
            app->scene = SceneDiscardConfirm;
            break;
        }
        if(e->key == InputKeyOk) {
            if(strlen(app->name_buf) == 0)
                strncpy(app->name_buf, "My Card", CARDVAULT_MAX_NAME - 1);
            app->menu_sel = 0;
            app->scene = SceneFolderPick;
            break;
        }
        {
            size_t len = strlen(app->name_buf);
            if(e->key == InputKeyRight) {
                if(len == 0) { app->name_buf[0] = 'A'; app->name_buf[1] = '\0'; }
                else {
                    char c = app->name_buf[len-1];
                    if(c=='Z') c='a'; else if(c=='z') c='0';
                    else if(c=='9') c=' '; else if(c==' ') c='A'; else c++;
                    app->name_buf[len-1] = c;
                }
            }
            if(e->key == InputKeyLeft && len > 0) app->name_buf[len-1] = '\0';
            if(e->key == InputKeyUp && len < CARDVAULT_MAX_NAME-1) {
                app->name_buf[len] = 'A'; app->name_buf[len+1] = '\0';
            }
            if(e->key == InputKeyDown && len > 0) {
                char c = app->name_buf[len-1];
                if(c=='A') c=' '; else if(c==' ') c='9';
                else if(c=='0') c='z'; else if(c=='a') c='Z'; else c--;
                app->name_buf[len-1] = c;
            }
        }
        break;

    case SceneDiscardConfirm:
        if(e->key == InputKeyBack) app->scene = SceneNameInput;  // back to keep editing
        if(e->key == InputKeyOk) {
            // Confirm discard
            discard_pending(app);
            app->scene = SceneHome;
        }
        if(e->key == InputKeyLeft) app->scene = SceneNameInput;
        if(e->key == InputKeyRight) {
            discard_pending(app);
            app->scene = SceneHome;
        }
        break;

    case SceneFolderPick:
        if(e->key == InputKeyBack) { app->scene = SceneNameInput; break; }
        if(e->key == InputKeyUp   && app->menu_sel > 0) app->menu_sel--;
        if(e->key == InputKeyDown && app->menu_sel < 4) app->menu_sel++;
        if(e->key == InputKeyOk) {
            furi_mutex_release(app->mutex);
            stop_scan(app);
            save_pending(app);
            // Persist to SD card
            if(app->card_count > 0) {
                cardvault_save_card(&app->cards[app->card_count - 1]);
            }
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->scene = SceneFolderView;
            app->card_sel = 0;
        }
        break;

    case SceneHealthCheck:
        if(e->key == InputKeyBack) app->scene = SceneCardDetail;
        break;

    default: break;
    }

    furi_mutex_release(app->mutex);
    view_port_update(app->view_port);
}

int32_t cardvault_app(void* p) {
    UNUSED(p);
    CardVaultApp* app = malloc(sizeof(CardVaultApp));
    memset(app, 0, sizeof(CardVaultApp));
    app->running    = true;
    app->scene      = SceneHome;
    app->prev_scene = SceneHome;
    app->scan_mode  = ScanModeNFC;
    app->mutex      = furi_mutex_alloc(FuriMutexTypeNormal);
    app->event_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    app->view_port   = view_port_alloc();
    view_port_draw_callback_set(app->view_port, cardvault_draw_callback, app);
    view_port_input_callback_set(app->view_port, input_callback, app);
    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
    app->nfc = nfc_alloc();

    // Load saved cards from SD card
    cardvault_load_all(app);

    InputEvent event;
    while(app->running) {
        if(furi_message_queue_get(app->event_queue, &event, furi_ms_to_ticks(100)) == FuriStatusOk)
            handle_input(app, &event);
        view_port_update(app->view_port);
    }

    stop_scan(app);
    stop_emulation(app);
    discard_pending(app);
    for(uint8_t i = 0; i < app->card_count; i++) free_card_data(&app->cards[i]);
    nfc_free(app->nfc);
    gui_remove_view_port(app->gui, app->view_port);
    furi_record_close(RECORD_GUI);
    view_port_free(app->view_port);
    furi_message_queue_free(app->event_queue);
    furi_mutex_free(app->mutex);
    free(app);
    return 0;
}
