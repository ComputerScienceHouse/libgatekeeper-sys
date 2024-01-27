#![deny(warnings)]

use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr;

use apdu_core::{Command, Response};
use openssl::{encrypt::Decrypter, hash::MessageDigest, pkey::PKey, sign::Signer};
use rand::Rng;
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write};

pub mod ffi;
use crate::ffi::{BaudRate, Modulation, ModulationType, NfcProperty};

pub struct Nfc {
    context: *mut ffi::context_t,
}

#[derive(Debug)]
pub enum NfcError {
    Unknown,
    // SendMismatch,
    NonceMismatch,
    NoResponse,
    // CryptoError,
}

impl Display for NfcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use NfcError::*;
        match self {
            Unknown => write!(f, "Unknown error"),
            NonceMismatch => write!(f, "Nonce for mobile tag didn't match"),
            NoResponse => write!(f, "Didn't get a response from the mobile tag"),
        }
    }
}

impl Error for NfcError {}

impl Nfc {
    pub fn new() -> Option<Self> {
        let mut context_uninit = MaybeUninit::<*mut ffi::context_t>::uninit();
        let context = unsafe {
            ffi::nfc_init(context_uninit.as_mut_ptr());
            if context_uninit.as_mut_ptr().is_null() {
                return None;
            }
            context_uninit.assume_init()
        };

        Some(Nfc { context })
    }

    pub fn gatekeeper_device(&mut self, conn_str: String) -> Option<NfcDevice> {
        let device_string = CString::new(conn_str).unwrap();
        let device = unsafe {
            let device_ptr = ffi::nfc_open(self.context, device_string.as_ptr());
            if device_ptr.is_null() {
                return None;
            }
            device_ptr
        };
        Some(NfcDevice {
            device,
            _context: self,
        })
    }
}

impl Drop for Nfc {
    fn drop(&mut self) {
        unsafe {
            ffi::nfc_exit(self.context);
        }
    }
}

pub struct NfcDevice<'a> {
    device: *mut ffi::device_t,
    _context: &'a Nfc,
}

const NONCE_LENGTH: usize = 8;
const RESPONSE_PADDING_LENGTH: usize = 2;

pub struct MobileNfcTag {
    nonce: [u8; NONCE_LENGTH],
    _target_guard: NfcTargetGuard,
}

struct NfcTargetGuard {
    device: *mut ffi::device_t,
}

impl Drop for NfcTargetGuard {
    fn drop(&mut self) {
        unsafe {
            let ecode = ffi::nfc_initiator_deselect_target(self.device);
            if ecode != 0 {
                eprintln!("Couldn't deslect target!! {}", ecode);
                let msg = CString::new("Deselect target :(").unwrap();
                ffi::nfc_perror(self.device, msg.as_ptr());
            }
        }
    }
}

impl<'b> NfcDevice<'b> {
    pub fn authenticate_tag(&self, realm: &mut Realm) -> Result<Option<String>, NfcError> {
        if let Some(mut tag) = self.first_tag() {
            tag.authenticate(self, realm).map(Some)
        } else if let Some(mut tag) = self.first_mobile_tag(realm) {
            tag.authenticate(self, realm).map(Some)
        } else {
            Ok(None)
        }
    }
    pub fn first_tag(&self) -> Option<FreefareNfcTag> {
        let (tags, tag) = unsafe {
            let tags = ffi::freefare_get_tags(self.device);
            if tags.is_null() {
                return None;
            }

            let tag = *tags;
            if tag.is_null() {
                return None;
            }
            (tags, tag)
        };

        Some(FreefareNfcTag {
            tags,
            tag,
            _device_lifetime: PhantomData,
        })
    }
    pub fn first_mobile_tag(&self, realm: &Realm) -> Option<MobileNfcTag> {
        if unsafe { ffi::nfc_initiator_init(self.device) } < 0 {
            eprintln!("Couldn't init NFC initiator!!!");
            unsafe {
                let msg = CString::new("Init NFC initiator :(").unwrap();
                ffi::nfc_perror(self.device, msg.as_ptr())
            };
            return None;
        }

        unsafe {
            ffi::nfc_device_set_property_bool(self.device, NfcProperty::NP_ACTIVATE_FIELD, 1)
        };
        unsafe {
            ffi::nfc_device_set_property_bool(self.device, NfcProperty::NP_INFINITE_SELECT, 0)
        };

        unsafe {
            let mut nt = MaybeUninit::uninit();
            if ffi::nfc_initiator_select_passive_target(
                self.device,
                Modulation {
                    nmt: ModulationType::NMT_ISO14443A,
                    nbr: BaudRate::NBR_106,
                },
                std::ptr::null(),
                0,
                nt.as_mut_ptr(),
            ) <= 0
            {
                // println!("No tag found");
                return None;
            }
        }
        let guard = NfcTargetGuard {
            device: self.device,
        };

        let response = self
            .send(Command::new_with_payload_le(
                0x00,
                0xA4,
                0x04,
                0x00,
                (NONCE_LENGTH + RESPONSE_PADDING_LENGTH) as u16,
                vec![0xf0, 0x63, 0x73, 0x68, 0x72, 0x69, 0x74 + realm.slot],
            ))
            .ok()?;
        if let Some(response) = response {
            if response.payload.len() != NONCE_LENGTH {
                return None;
            }
            let nonce = &response.payload[0..NONCE_LENGTH];
            let mut nonce_arr: [u8; NONCE_LENGTH] = Default::default();
            nonce_arr.copy_from_slice(nonce);
            Some(MobileNfcTag {
                nonce: nonce_arr,
                _target_guard: guard,
            })
        } else {
            None
        }
    }
    pub fn send(&self, command: Command) -> Result<Option<Response>, NfcError> {
        let mut response = vec![0u8; command.le.unwrap_or(0).into()];
        let command: Vec<u8> = command.into();
        let response_size = unsafe {
            ffi::nfc_initiator_transceive_bytes(
                self.device,
                command.as_ptr(),
                command.len(),
                response.as_mut_ptr(),
                response.len(),
                2000,
            )
        };
        if response_size < 0 {
            return Err(NfcError::Unknown);
        }
        if response_size == 0 {
            return Ok(None);
        }
        // convert response to a vec, from 0..response_size:
        response.truncate(response_size as usize);

        Ok(Some(Response::from(response)))
    }
}

fn sign_message(realm: &Realm, message: &[u8]) -> Result<Vec<u8>, NfcError> {
    // Sign message using the PKCS#8 encoded EC key realm.private_key using SHA256
    let pkey = PKey::private_key_from_pem(
        CString::new(realm.signing_private_key.clone())
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
    signer.update(message).unwrap();
    Ok(signer.sign_to_vec().unwrap())
}

fn decrypt_message(realm: &Realm, message: &[u8]) -> Result<Vec<u8>, NfcError> {
    let pkey = PKey::private_key_from_pem(
        CString::new(realm.asymmetric_private_key.clone())
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let decrypter = Decrypter::new(pkey.as_ref()).unwrap();
    let message_len = decrypter.decrypt_len(message).unwrap();
    let mut output = vec![0; message_len];
    let length = decrypter.decrypt(message, output.as_mut_slice()).unwrap();
    Ok(output[..length].into())
}

impl NfcTag for MobileNfcTag {
    fn authenticate(
        &mut self,
        nfc_device: &NfcDevice<'_>,
        realm: &mut Realm,
    ) -> Result<String, NfcError> {
        println!("Authenticating! Sending signed nonce");
        println!("{} is the realm id", realm.slot);
        // Concatenate self.nonce and our_nonce
        let our_nonce = rand::thread_rng().gen::<[u8; NONCE_LENGTH]>();
        let mut signature_data = [0u8; NONCE_LENGTH * 2];
        signature_data[0..NONCE_LENGTH].copy_from_slice(&self.nonce);
        signature_data[NONCE_LENGTH..].copy_from_slice(&our_nonce);
        let mut signature = sign_message(realm, &signature_data)?;
        // Add our_nonce to signature
        signature.extend_from_slice(&our_nonce);

        let encrypted_association = nfc_device
            .send(Command::new_with_payload_le(
                0xD0, 0x00, 0x00, 0x00, // Encrypted value length is non-determinate
                512, signature,
            ))?
            .ok_or(NfcError::NoResponse)?;
        let payload = encrypted_association.payload.as_slice();
        let payload = decrypt_message(realm, payload)?;
        // take last 8 bytes of association as the nonce
        let nonce = &payload[payload.len() - self.nonce.len()..payload.len()];
        // take the rest as the association
        let association_id = &payload[0..payload.len() - self.nonce.len()];

        if our_nonce != nonce {
            return Err(NfcError::NonceMismatch);
        }

        Ok(association_id
            .iter()
            .fold(String::new(), |mut collector, id| {
                write!(collector, "{:02x}", id).unwrap();
                collector
            }))
    }
}

impl Drop for NfcDevice<'_> {
    fn drop(&mut self) {
        unsafe {
            ffi::nfc_close(self.device);
        }
    }
}

pub struct FreefareNfcTag<'a> {
    tags: *mut *mut ffi::mifare_t,
    tag: *mut ffi::mifare_t,
    _device_lifetime: std::marker::PhantomData<&'a ()>,
}

pub trait NfcTag {
    fn authenticate(
        &mut self,
        nfc_device: &NfcDevice<'_>,
        realm: &mut Realm,
    ) -> Result<String, NfcError>;
}

impl NfcTag for FreefareNfcTag<'_> {
    // TODO: None of this is super ideal...
    fn authenticate(
        &mut self,
        _nfc_device: &NfcDevice<'_>,
        realm: &mut Realm,
    ) -> Result<String, NfcError> {
        let mut association_id = [0u8; 37];
        let auth_result =
            unsafe { ffi::authenticate_tag(self.tag, realm.realm, association_id.as_mut_ptr()) };
        if auth_result == 0 {
            return Err(NfcError::Unknown);
        }

        let mut association_id = association_id.to_vec();
        // Pop off NUL byte
        association_id.pop();

        Ok(String::from_utf8(association_id).unwrap())
    }
}

impl FreefareNfcTag<'_> {
    pub fn get_uid(&mut self) -> Option<String> {
        unsafe {
            let tag_uid = ffi::freefare_get_tag_uid(self.tag);
            if tag_uid.is_null() {
                return None;
            }
            let tag_uid_string = CString::from_raw(tag_uid);
            Some(tag_uid_string.to_string_lossy().to_string())
        }
    }

    pub fn get_friendly_name(&mut self) -> Option<&str> {
        unsafe {
            let tag_name = ffi::freefare_get_tag_friendly_name(self.tag);
            let tag_name_string = CStr::from_ptr(tag_name);
            tag_name_string.to_str().ok()
        }
    }

    pub fn format(
        &mut self,
        uid: Option<&str>,
        system_secret: Option<&str>,
    ) -> Result<(), NfcError> {
        let uid_opt = match uid {
            Some(uid) => CString::new(uid).ok(),
            None => None,
        };
        let uid = match &uid_opt {
            Some(uid) => uid.as_ptr(),
            None => ptr::null(),
        };
        let system_secret_opt = match system_secret {
            Some(system_secret) => CString::new(system_secret).ok(),
            None => None,
        };
        let system_secret = match &system_secret_opt {
            Some(system_secret) => system_secret.as_ptr(),
            None => ptr::null(),
        };

        unsafe {
            let format_result = ffi::format_tag(self.tag, uid, system_secret);
            if format_result != 0 {
                return Err(NfcError::Unknown);
            }
            Ok(())
        }
    }

    pub fn issue(
        &mut self,
        system_secret: &str,
        uid: Option<&str>,
        in_realms: Vec<&mut Realm>,
    ) -> Result<(), NfcError> {
        let system_secret = CString::new(system_secret).unwrap();
        let uid_opt = match uid {
            Some(uid) => CString::new(uid).ok(),
            None => None,
        };
        let uid = match &uid_opt {
            Some(uid) => uid.as_ptr(),
            None => ptr::null(),
        };

        let mut realms: Vec<*mut ffi::realm_t> = Vec::with_capacity(in_realms.len());
        for realm in in_realms {
            realms.push(realm.realm);
        }
        unsafe {
            let issue_result = ffi::issue_tag(
                self.tag,
                system_secret.as_ptr(),
                uid,
                realms.as_mut_ptr(),
                realms.len(),
            );
            if issue_result != 0 {
                return Err(NfcError::Unknown);
            }
            Ok(())
        }
    }
}

impl Drop for FreefareNfcTag<'_> {
    fn drop(&mut self) {
        unsafe {
            ffi::freefare_free_tags(self.tags);
        }
    }
}

pub struct Realm {
    realm: *mut ffi::realm_t,
    slot: u8,
    signing_private_key: String,
    asymmetric_private_key: String,
}

// A realm is a global thing, it's not tied to a card.
// Keys here are secrets for that particular project (e.g. drink, gatekeeper)
// Most likely, the only thing you want to change here is 'association' for each card
impl Realm {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        slot: u8,
        name: &str,
        association: &str,
        auth_key: &str,
        read_key: &str,
        update_key: &str,
        public_key: &str,
        private_key: &str,
        mobile_private_key: &str,
        asymmetric_private_key: &str,
    ) -> Option<Realm> {
        let ffi_name = CString::new(name).ok()?;
        let ffi_association = CString::new(association).ok()?;
        let ffi_auth_key = CString::new(auth_key).ok()?;
        let ffi_read_key = CString::new(read_key).ok()?;
        let ffi_update_key = CString::new(update_key).ok()?;
        let ffi_public_key = CString::new(public_key).ok()?;
        let ffi_private_key = CString::new(private_key).ok()?;

        let realm = unsafe {
            ffi::realm_create(
                slot,
                ffi_name.as_ptr(),
                ffi_association.as_ptr(),
                ffi_auth_key.as_ptr(),
                ffi_read_key.as_ptr(),
                ffi_update_key.as_ptr(),
                ffi_public_key.as_ptr(),
                ffi_private_key.as_ptr(),
            )
        };

        Some(Realm {
            realm,
            slot,
            signing_private_key: mobile_private_key.to_string(),
            asymmetric_private_key: asymmetric_private_key.to_string(),
        })
    }
}

impl Drop for Realm {
    fn drop(&mut self) {
        unsafe {
            ffi::realm_free(self.realm);
        }
    }
}
