#include "cardvault.h"

const char* security_label(SecurityRating r);
void        security_bar(SecurityRating r, char* out, size_t len);
const char* emulation_label(EmulationLevel e);

static void draw_header(Canvas* canvas, const char* title) {
    canvas_draw_rbox(canvas, 0, 0, 128, 13, 3);
    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 10, AlignCenter, AlignBottom, title);
    canvas_set_color(canvas, ColorBlack);
}

static void draw_footer(Canvas* canvas, const char* text) {
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 63, AlignCenter, AlignBottom, text);
}

static const char* tech_short(CardTech t) {
    switch(t) {
    case CardTechMifareClassic:    return "MIFARE Classic";
    case CardTechMifareClassic4K:  return "MIFARE Classic 4K";
    case CardTechMifareUltralight: return "MIFARE UL";
    case CardTechMifareUltralightC:return "MIFARE UL-C";
    case CardTechMifarePlus:       return "MIFARE Plus";
    case CardTechMifareDESFire:    return "DESFire";
    case CardTechNTAG203:          return "NTAG203";
    case CardTechNTAG213:          return "NTAG213";
    case CardTechNTAG215:          return "NTAG215";
    case CardTechNTAG216:          return "NTAG216";
    case CardTechNTAGI2C:          return "NTAG I2C";
    case CardTechEMV:              return "EMV Bank";
    case CardTechFelica:           return "FeliCa";
    case CardTechFelicaLite:       return "FeliCa Lite";
    case CardTechISO14443A:        return "ISO 14443A";
    case CardTechISO14443B:        return "ISO 14443B";
    case CardTechCalypso:          return "Calypso";
    case CardTechISO15693:         return "ISO 15693";
    case CardTechSLIX:             return "SLIX";
    case CardTechSLIX2:            return "SLIX2";
    case CardTechST25TB:           return "ST25TB";
    case CardTechEM4100:           return "EM4100";
    case CardTechHIDProx:          return "HID Prox";
    case CardTechIndala:           return "Indala";
    case CardTechAWID:             return "AWID";
    case CardTechIoProx:           return "IoProx";
    case CardTechParadox:          return "Paradox";
    case CardTechViking:           return "Viking";
    case CardTechRFID125Generic:   return "125kHz RFID";
    default:                       return "Unknown";
    }
}

static const char* freq_label(CardTech t) {
    if(t >= CardTechEM4100) return "125 kHz";
    if(t == CardTechUnknown) return "?";
    return "13.56 MHz";
}

// ─── HOME ─────────────────────────────────────────────────────────────────────
static void draw_home(Canvas* canvas, CardVaultApp* app) {
    draw_header(canvas, "CardVault");
    uint8_t counts[5] = {0};
    for(uint8_t i = 0; i < app->card_count; i++)
        if(app->cards[i].valid && app->cards[i].folder < 5)
            counts[app->cards[i].folder]++;

    uint8_t tab_w = 25;
    for(uint8_t i = 0; i < 5; i++) {
        int tx = 1 + i * (tab_w + 1);
        bool sel = (i == app->folder_sel);
        if(sel) canvas_draw_rbox(canvas, tx, 15, tab_w, 22, 3);
        else    canvas_draw_rframe(canvas, tx, 15, tab_w, 22, 3);
        canvas_set_color(canvas, sel ? ColorWhite : ColorBlack);
        canvas_set_font(canvas, FontSecondary);
        char abbrev[5] = {0};
        strncpy(abbrev, FOLDER_NAMES[i], 4);
        canvas_draw_str_aligned(canvas, tx + tab_w / 2, 24, AlignCenter, AlignCenter, abbrev);
        char cnt[4];
        snprintf(cnt, sizeof(cnt), "%d", counts[i]);
        canvas_draw_str_aligned(canvas, tx + tab_w / 2, 33, AlignCenter, AlignCenter, cnt);
        canvas_set_color(canvas, ColorBlack);
    }

    canvas_set_font(canvas, FontSecondary);
    char total[24];
    snprintf(total, sizeof(total), "%d card%s total", app->card_count,
             app->card_count == 1 ? "" : "s");
    canvas_draw_str_aligned(canvas, 64, 48, AlignCenter, AlignCenter, total);
    draw_footer(canvas, "[<][>] Folder [OK] Open [v] Scan");
}

// ─── FOLDER VIEW ──────────────────────────────────────────────────────────────
static void draw_folder(Canvas* canvas, CardVaultApp* app) {
    draw_header(canvas, FOLDER_NAMES[app->folder_sel]);
    uint8_t indices[CARDVAULT_MAX_CARDS];
    uint8_t count = 0;
    for(uint8_t i = 0; i < app->card_count; i++)
        if(app->cards[i].valid && app->cards[i].folder == app->folder_sel)
            indices[count++] = i;

    if(count == 0) {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, 35, AlignCenter, AlignCenter, "No cards here yet");
        draw_footer(canvas, "[Back] Home  [v] Scan new");
        return;
    }

    if(app->card_sel >= count) app->card_sel = count - 1;
    uint8_t start = app->card_sel > 1 ? app->card_sel - 1 : 0;
    if(start + 3 > count) start = count > 3 ? count - 3 : 0;

    uint8_t y = 17;
    for(uint8_t i = start; i < count && i < start + 3; i++) {
        VaultCard* c = &app->cards[indices[i]];
        bool sel = (i == app->card_sel);
        if(sel) {
            canvas_draw_rbox(canvas, 0, y - 1, 128, 13, 2);
            canvas_set_color(canvas, ColorWhite);
        }
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 4, y + 8, c->name);
        canvas_draw_str_aligned(canvas, 124, y + 8, AlignRight, AlignBottom, tech_short(c->tech));
        canvas_set_color(canvas, ColorBlack);
        y += 14;
    }
    draw_footer(canvas, "[OK] Detail  [Back] Home");
}

// ─── CARD DETAIL ──────────────────────────────────────────────────────────────
static void draw_card_detail(Canvas* canvas, CardVaultApp* app) {
    uint8_t indices[CARDVAULT_MAX_CARDS];
    uint8_t count = 0;
    for(uint8_t i = 0; i < app->card_count; i++)
        if(app->cards[i].valid && app->cards[i].folder == app->folder_sel)
            indices[count++] = i;
    if(count == 0 || app->card_sel >= count) return;
    VaultCard* c = &app->cards[indices[app->card_sel]];

    draw_header(canvas, c->name);
    canvas_set_font(canvas, FontSecondary);

    char line1[40];
    snprintf(line1, sizeof(line1), "%s  %s", tech_short(c->tech), freq_label(c->tech));
    canvas_draw_str(canvas, 2, 23, line1);
    canvas_draw_str(canvas, 2, 33, "UID:");
    canvas_draw_str(canvas, 26, 33, c->uid_str);

    // For EMV cards, show the brand label instead of the emulation status here
    if(c->tech == CardTechEMV && c->emv_pan[0] != '\0') {
        canvas_draw_str(canvas, 2, 43, c->emv_pan);
    } else {
        char emu_line[28];
        snprintf(emu_line, sizeof(emu_line), "Emulation: %s", emulation_label(c->emu_level));
        canvas_draw_str(canvas, 2, 43, emu_line);
    }

    char sec_bar[8];
    security_bar(c->security, sec_bar, sizeof(sec_bar));
    char sec_line[32];
    snprintf(sec_line, sizeof(sec_line), "%s %s", sec_bar, security_label(c->security));
    canvas_draw_str(canvas, 2, 53, sec_line);

    if(c->emu_level == EmulationUIDOnly)
        draw_footer(canvas, "[OK] Emulate  [^] Health");
    else
        draw_footer(canvas, "[^] Health  [v] Del  [Back]");
}

// ─── SCAN ─────────────────────────────────────────────────────────────────────
static void draw_scan(Canvas* canvas, CardVaultApp* app) {
    draw_header(canvas, "Scan Card");

    bool nfc_sel = (app->scan_mode == ScanModeNFC);
    if(nfc_sel) canvas_draw_rbox(canvas, 14, 15, 44, 12, 3);
    else        canvas_draw_rframe(canvas, 14, 15, 44, 12, 3);
    canvas_set_color(canvas, nfc_sel ? ColorWhite : ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 36, 21, AlignCenter, AlignCenter, "NFC 13.56");
    canvas_set_color(canvas, ColorBlack);

    if(!nfc_sel) canvas_draw_rbox(canvas, 70, 15, 44, 12, 3);
    else         canvas_draw_rframe(canvas, 70, 15, 44, 12, 3);
    canvas_set_color(canvas, !nfc_sel ? ColorWhite : ColorBlack);
    canvas_draw_str_aligned(canvas, 92, 21, AlignCenter, AlignCenter, "RFID 125k");
    canvas_set_color(canvas, ColorBlack);

    canvas_set_font(canvas, FontSecondary);
    if(app->scan_done && app->scan_success) {
        canvas_set_font(canvas, FontPrimary);
        if(app->reading_full) {
            canvas_draw_str_aligned(canvas, 64, 32, AlignCenter, AlignCenter, "Reading data...");
            canvas_set_font(canvas, FontSecondary);
            canvas_draw_str_aligned(canvas, 64, 44, AlignCenter, AlignCenter, tech_short(app->pending.tech));
            canvas_draw_str_aligned(canvas, 64, 54, AlignCenter, AlignCenter, "Hold card steady");
            draw_footer(canvas, "[Back] Cancel");
        } else {
            canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter, "Card Found!");
            canvas_set_font(canvas, FontSecondary);
            canvas_draw_str_aligned(canvas, 64, 47, AlignCenter, AlignCenter,
                                    tech_short(app->pending.tech));
            canvas_draw_str_aligned(canvas, 64, 56, AlignCenter, AlignCenter,
                                    app->pending.uid_str);
            draw_footer(canvas, "[OK] Name it  [Back] Discard");
        }
    } else {
        char anim[12] = "Scanning";
        uint8_t dots = (app->frame / 6) % 4;
        for(uint8_t i = 0; i < dots; i++) anim[8 + i] = '.';
        anim[8 + dots] = '\0';
        canvas_draw_str_aligned(canvas, 64, 38, AlignCenter, AlignCenter, anim);
        canvas_draw_str_aligned(canvas, 64, 49, AlignCenter, AlignCenter, "Hold card to back");
        draw_footer(canvas, "[<][>] Mode  [Back] Cancel");
    }
}

// ─── NAME INPUT ───────────────────────────────────────────────────────────────
static void draw_name_input(Canvas* canvas, CardVaultApp* app) {
    draw_header(canvas, "Name This Card");
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 24, AlignCenter, AlignCenter, "Up/Dn=letter R=add L=delete");

    char display[CARDVAULT_MAX_NAME + 2];
    strncpy(display, app->name_buf, sizeof(display) - 2);
    size_t len = strlen(display);
    display[len] = '_'; display[len + 1] = '\0';
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 42, AlignCenter, AlignCenter, display);
    draw_footer(canvas, "[OK] Confirm  [Back] Cancel");
}

// ─── FOLDER PICK ──────────────────────────────────────────────────────────────
static void draw_folder_pick(Canvas* canvas, CardVaultApp* app) {
    draw_header(canvas, "Choose Folder");
    uint8_t y = 18;
    for(uint8_t i = 0; i < 5; i++) {
        bool sel = (i == app->menu_sel);
        if(sel) {
            canvas_draw_rbox(canvas, 10, y - 7, 108, 10, 2);
            canvas_set_color(canvas, ColorWhite);
        }
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, y, AlignCenter, AlignCenter, FOLDER_NAMES[i]);
        canvas_set_color(canvas, ColorBlack);
        y += 11;
    }
    draw_footer(canvas, "[OK] Select  [Back] Cancel");
}

// ─── HEALTH ──────────────────────────────────────────────────────────────────
static void draw_health(Canvas* canvas, CardVaultApp* app) {
    uint8_t indices[CARDVAULT_MAX_CARDS];
    uint8_t count = 0;
    for(uint8_t i = 0; i < app->card_count; i++)
        if(app->cards[i].valid && app->cards[i].folder == app->folder_sel)
            indices[count++] = i;
    if(count == 0 || app->card_sel >= count) return;
    VaultCard* c = &app->cards[indices[app->card_sel]];

    draw_header(canvas, "Health Check");

    char sec_bar[8];
    security_bar(c->security, sec_bar, sizeof(sec_bar));
    char badge[32];
    snprintf(badge, sizeof(badge), "%s %s", sec_bar, security_label(c->security));

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 23, c->health_title);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 32, badge);

    const char* body = c->health_body;
    uint8_t y = 42;
    while(*body && y < 62) {
        char chunk[22];
        strncpy(chunk, body, 21); chunk[21] = '\0';
        size_t clen = strlen(body);
        if(clen > 21) {
            char* sp = strrchr(chunk, ' ');
            if(sp) { *sp = '\0'; body += strlen(chunk) + 1; }
            else body += 21;
        } else {
            body += clen;
        }
        canvas_draw_str(canvas, 2, y, chunk);
        y += 9;
    }
    draw_footer(canvas, "[Back] Return");
}

// ─── EMULATING ────────────────────────────────────────────────────────────────
static void draw_emulating(Canvas* canvas, CardVaultApp* app) {
    VaultCard* c = &app->cards[app->last_used_idx < app->card_count ? app->last_used_idx : 0];

    draw_header(canvas, "Emulating");

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 26, AlignCenter, AlignCenter, c->name);
    canvas_set_font(canvas, FontSecondary);

    char sub[40];
    snprintf(sub, sizeof(sub), "%s  UID only", tech_short(c->tech));
    canvas_draw_str_aligned(canvas, 64, 38, AlignCenter, AlignCenter, sub);
    canvas_draw_str_aligned(canvas, 64, 48, AlignCenter, AlignCenter, c->uid_str);

    // Pulsing transmit ring
    uint8_t r = 3 + (app->frame % 8);
    canvas_draw_circle(canvas, 14, 47, r);
    canvas_draw_circle(canvas, 114, 47, r);

    draw_footer(canvas, "[OK/Back] Stop");
}


// ─── DISCARD CONFIRM ──────────────────────────────────────────────────────────
static void draw_discard_confirm(Canvas* canvas, CardVaultApp* app) {
    UNUSED(app);
    draw_header(canvas, "Discard Card?");
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 26, AlignCenter, AlignCenter, "Throw away the scanned");
    canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter, "card without saving?");
    canvas_draw_str_aligned(canvas, 64, 50, AlignCenter, AlignCenter, "[<] Keep editing");
    canvas_draw_str_aligned(canvas, 64, 58, AlignCenter, AlignCenter, "[>] or [OK] Discard");
}

// ─── MASTER ───────────────────────────────────────────────────────────────────
void cardvault_draw_callback(Canvas* canvas, void* ctx) {
    CardVaultApp* app = ctx;
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->frame++;

    switch(app->scene) {
    case SceneHome:        draw_home(canvas, app);        break;
    case SceneFolderView:  draw_folder(canvas, app);      break;
    case SceneCardDetail:  draw_card_detail(canvas, app); break;
    case SceneScan:        draw_scan(canvas, app);        break;
    case SceneNameInput:   draw_name_input(canvas, app);  break;
    case SceneFolderPick:  draw_folder_pick(canvas, app); break;
    case SceneHealthCheck: draw_health(canvas, app);      break;
    case SceneEmulating:   draw_emulating(canvas, app);   break;
    case SceneDiscardConfirm: draw_discard_confirm(canvas, app); break;
    default: break;
    }

    furi_mutex_release(app->mutex);
}
