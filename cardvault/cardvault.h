#pragma once

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <input/input.h>
#include <nfc/nfc.h>
#include <nfc/nfc_poller.h>
#include <nfc/nfc_listener.h>
#include <nfc/nfc_scanner.h>
#include <nfc/nfc_device.h>
#include <stdlib.h>
#include <string.h>

#define CARDVAULT_MAX_CARDS   32        // reduced from 64 since we store more per card
#define CARDVAULT_MAX_NAME    24
#define CARDVAULT_FOLDERS     5

typedef enum {
    CardTechUnknown = 0,
    CardTechMifareClassic,
    CardTechMifareClassic4K,
    CardTechMifareUltralight,
    CardTechMifareUltralightC,
    CardTechMifarePlus,
    CardTechMifareDESFire,
    CardTechNTAG203,
    CardTechNTAG213,
    CardTechNTAG215,
    CardTechNTAG216,
    CardTechNTAGI2C,
    CardTechEMV,
    CardTechISO14443A,
    CardTechISO14443B,
    CardTechCalypso,
    CardTechISO15693,
    CardTechSLIX,
    CardTechSLIX2,
    CardTechST25TB,
    CardTechFelica,
    CardTechFelicaLite,
    CardTechEM4100,
    CardTechHIDProx,
    CardTechIndala,
    CardTechAWID,
    CardTechIoProx,
    CardTechParadox,
    CardTechViking,
    CardTechRFID125Generic,
} CardTech;

typedef enum {
    SecurityBroken = 0,
    SecurityWeak,
    SecurityModerate,
    SecurityStrong,
    SecurityUnknown,
} SecurityRating;

typedef enum {
    ScanModeNFC = 0,
    ScanModeRFID,
} ScanMode;

typedef enum {
    EmulationNone = 0,
    EmulationUIDOnly,
    EmulationFull,        // we have the full memory dump
} EmulationLevel;

static const char* const FOLDER_NAMES[5] = {
    "Work", "Home", "Gym", "Travel", "Other",
};

typedef struct {
    bool     valid;
    char     name[CARDVAULT_MAX_NAME];
    uint8_t  folder;
    CardTech tech;
    uint8_t  uid[10];
    uint8_t  uid_len;
    char     uid_str[32];
    uint8_t  atqa[2];
    uint8_t  sak;
    uint32_t rfid_data;
    bool     is_rfid;
    EmulationLevel emu_level;

    // Full card data — dynamically allocated based on protocol
    // For MIFARE Ultralight / NTAG: pointer to MfUltralightData
    // For EMV: NULL (we only store UID + PAN/expiry strings below)
    void*    full_data;
    NfcProtocol full_data_protocol;

    // EMV-specific display fields
    char     emv_pan[24];       // e.g. "4111 **** **** 1234"
    char     emv_expiry[8];     // e.g. "12/26"

    uint32_t scanned_tick;
    uint32_t last_used_tick;
    int8_t   scan_rssi;
    SecurityRating security;
    char     health_title[32];
    char     health_body[128];
} VaultCard;

typedef enum {
    SceneHome = 0,
    SceneFolderView,
    SceneCardDetail,
    SceneScan,
    SceneScanReading,    // showing "Reading card data..." after detection
    SceneNameInput,
    SceneFolderPick,
    SceneHealthCheck,
    SceneEmulating,
    SceneDiscardConfirm,  // confirm discarding card during naming
    SceneCount,
} AppScene;

typedef struct {
    Gui*              gui;
    ViewPort*         view_port;
    FuriMessageQueue* event_queue;
    FuriMutex*        mutex;
    Nfc*              nfc;
    NfcPoller*        poller;
    NfcListener*      listener;
    NfcDevice*        emu_device;
    FuriThread*       scan_thread;
    bool              nfc_active;
    bool              emu_active;
    AppScene          scene;
    AppScene          prev_scene;
    bool              running;
    VaultCard         cards[CARDVAULT_MAX_CARDS];
    uint8_t           card_count;
    uint8_t           last_used_idx;
    uint8_t           folder_sel;
    uint8_t           card_sel;
    uint8_t           menu_sel;
    VaultCard         pending;
    bool              scan_done;
    bool              scan_success;
    bool              reading_full;     // currently doing phase-2 full read
    ScanMode          scan_mode;
    char              name_buf[CARDVAULT_MAX_NAME];
    uint32_t          frame;
} CardVaultApp;
