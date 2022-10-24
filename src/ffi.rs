#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_void};

pub type context_t = c_void;
pub type mifare_t = c_void;
pub type device_t = c_void;
pub type realm_t = c_void;
#[repr(u32)]
pub enum BaudRate {
    NBR_UNDEFINED = 0,
    NBR_106 = 1,
    NBR_212 = 2,
    NBR_424 = 3,
    NBR_847 = 4,
}
#[derive(Copy, Clone)]
#[repr(u32)]
pub enum ModulationType {
    NMT_ISO14443A = 1,
    NMT_JEWEL = 2,
    NMT_ISO14443B = 3,
    NMT_ISO14443BI = 4,
    NMT_ISO14443B2SR = 5,
    NMT_ISO14443B2CT = 6,
    NMT_FELICA = 7,
    NMT_DEP = 8,
}
#[repr(C)]
pub struct Modulation {
    pub nmt: ModulationType,
    pub nbr: BaudRate,
}
pub type modulation_t = Modulation;
#[repr(C)]
//#[derive(Copy, Clone)]
pub struct Union_Unnamed11 {
    pub _bindgen_data_: [u8; 283usize],
}
pub type nfc_target_info = Union_Unnamed11;
#[repr(C)]
pub struct NfcTarget {
    pub nti: nfc_target_info,
    pub nm: modulation_t,
}
pub type nfc_target = NfcTarget;
#[derive(Copy, Clone)]
#[repr(u32)]
pub enum NfcProperty {
    NP_TIMEOUT_COMMAND = 0,
    NP_TIMEOUT_ATR = 1,
    NP_TIMEOUT_COM = 2,
    NP_HANDLE_CRC = 3,
    NP_HANDLE_PARITY = 4,
    NP_ACTIVATE_FIELD = 5,
    NP_ACTIVATE_CRYPTO1 = 6,
    NP_INFINITE_SELECT = 7,
    NP_ACCEPT_INVALID_FRAMES = 8,
    NP_ACCEPT_MULTIPLE_FRAMES = 9,
    NP_AUTO_ISO14443_4 = 10,
    NP_EASY_FRAMING = 11,
    NP_FORCE_ISO14443_A = 12,
    NP_FORCE_ISO14443_B = 13,
    NP_FORCE_SPEED_106 = 14,
}
pub type nfc_property = NfcProperty;

#[link(name = "gatekeeper")]
extern "C" {
    pub fn realm_create(
        slot: u8,
        name: *const c_char,
        association_id: *const c_char,
        auth_key: *const c_char,
        read_key: *const c_char,
        update_key: *const c_char,
        public_key: *const c_char,
        private_key: *const c_char,
    ) -> *mut realm_t;

    pub fn realm_free(realm: *mut realm_t);

    pub fn format_tag(tag: *mut mifare_t, uid: *const c_char, system_secret: *const c_char) -> i32;

    pub fn issue_tag(
        tag: *mut mifare_t,
        system_secret: *const c_char,
        uid: *const c_char,
        realms: *mut *mut c_void,
        num_realms: usize,
    ) -> i32;

    pub fn authenticate_tag(
        tag: *mut mifare_t,
        realm: *mut realm_t,
        association_id: *mut u8,
    ) -> i32;
}

#[link(name = "nfc")]
extern "C" {
    pub fn nfc_init(context: *mut *mut context_t);
    pub fn nfc_list_devices(
        context: *mut context_t,
        devices: *mut *const c_char,
        device_count: usize,
    ) -> u32;
    pub fn nfc_open(context: *mut context_t, device_id: *const c_char) -> *mut device_t;
    pub fn nfc_perror(device: *const device_t, message: *const c_char);
    pub fn nfc_initiator_init(device: *mut device_t) -> c_int;
    pub fn nfc_close(context: *mut device_t);
    pub fn nfc_exit(context: *mut context_t);
    pub fn nfc_initiator_transceive_bytes(
        device: *mut device_t,
        bytes: *const u8,
        byte_count: usize,
        rx_bytes: *const u8,
        rx_byte_count: usize,
        timeout: c_int,
    ) -> c_int;
    pub fn nfc_initiator_select_passive_target(
        device: *mut device_t,
        nfc_modulation: modulation_t,
        pbt_init_data: *const u8,
        sz_init_data: usize,
        pnt: *mut nfc_target,
    ) -> c_int;
    pub fn nfc_initiator_deselect_target(device: *mut device_t) -> c_int;
    pub fn nfc_device_set_property_bool(
        pnd: *mut device_t,
        property: nfc_property,
        bEnable: u8,
    ) -> c_int;
}

#[link(name = "freefare")]
extern "C" {
    pub fn freefare_get_tags(device: *const device_t) -> *mut *mut mifare_t;
    pub fn freefare_get_tag_type(tag: *mut mifare_t) -> i8;
    pub fn freefare_get_tag_uid(tag: *mut mifare_t) -> *mut c_char;
    pub fn freefare_get_tag_friendly_name(tag: *mut mifare_t) -> *const c_char;
    pub fn freefare_free_tags(tags: *mut *mut mifare_t);
    pub fn free(data: *mut c_void);
}
