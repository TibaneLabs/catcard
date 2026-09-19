//! The board's firmware-staging area, and how an approved image is installed.
//!
//! Where a pending image is written before the reboot that installs it differs by
//! generation, so this is the one place that knows which:
//!
//! - **mk4 / mk5 / Q1** stage into **PSRAM** and install through `gate 18/7`, which
//!   authorises the staged region and reboots. [`catcard_upgrade::psram`].
//! - **mk3** has no PSRAM: it stages into **SPI-NOR** from offset 0, and the bootloader
//!   installs whatever is staged there on the next boot. There is no `gate 18/7` — the
//!   trailing "upload complete" header that `commit` wrote is the trigger, so installing
//!   is simply rebooting. [`catcard_upgrade::nor`].
//!
//! Everything above this — receiving the image, the header/signature checks, the approval
//! screen — is board-agnostic and shared, exactly as it should be.

use catcard_callgate::Callgate;
#[cfg(feature = "board-mk3")]
use catcard_callgate::abi::LogoutMode;
use catcard_upgrade::StagingArea;
#[cfg(feature = "board-mk3")]
use catcard_upgrade::claim::{Claim, Ticket};

use crate::display;

/// The medium itself, before anything claims it.
#[cfg(not(feature = "board-mk3"))]
type Medium = catcard_upgrade::psram::PsramArea;
#[cfg(feature = "board-mk3")]
type Medium = catcard_upgrade::nor::NorArea<crate::nor::NorBus>;

/// One holder at a time for the **mk3's** SPI-NOR.
///
/// Every other board stages into PSRAM, which is claimed through [`crate::psram`]
/// because several unrelated things want it. The mk3's flash is wanted by staging
/// alone, so it keeps its own claim rather than pretending to be part of a resource
/// that board does not have.
#[cfg(feature = "board-mk3")]
static HELD: Claim = Claim::new();

/// The tag the mk3's claim is taken under. It has one holder, but a claim will not be
/// taken anonymously -- a holder that cannot be named is one a refusal cannot explain.
#[cfg(feature = "board-mk3")]
const NOR_STAGING: u8 = 1;

/// The board's staging area, held exclusively for as long as this lives.
///
/// The ticket is released when this is dropped, which is wherever the staging ends --
/// installed, declined, refused partway, or abandoned when a screen returns. Nothing has to
/// remember to hand it back.
pub struct Area {
    medium: Medium,
    /// What keeps the medium ours. On PSRAM boards this is the lease the rest of the
    /// firmware asks for too; on mk3 it is the SPI-NOR's own ticket.
    #[cfg(not(feature = "board-mk3"))]
    _lease: crate::psram::Lease,
    #[cfg(feature = "board-mk3")]
    _ticket: Ticket,
}

impl StagingArea for Area {
    type Error = <Medium as StagingArea>::Error;

    fn image_offset(&self) -> u32 {
        self.medium.image_offset()
    }

    fn capacity(&self) -> u32 {
        self.medium.capacity()
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), Self::Error> {
        self.medium.write(offset, data)
    }

    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error> {
        self.medium.read(offset, out)
    }

    fn publish(&mut self, len: u32) -> Result<(), Self::Error> {
        self.medium.publish(len)
    }
}

/// Why the staging area could not be had.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Unavailable {
    /// This board has no staging medium, or it did not answer.
    NoMedium,
    /// Something else has the medium. On a PSRAM board that is not necessarily another
    /// image: it may be a transaction being signed or a QR being read, and
    /// [`crate::psram::holder`] says which.
    Busy,
}

/// Whether this board has a firmware-staging medium at all -- a cheap const check (no
/// hardware brought up), for reporting the upgrade capability and refusing an offer early.
pub fn has_staging() -> bool {
    #[cfg(not(feature = "board-mk3"))]
    {
        catcard_board::BOARD.psram.is_some()
    }
    #[cfg(feature = "board-mk3")]
    {
        catcard_board::BOARD.sflash.is_some()
    }
}

/// Take the board's firmware-staging area, exclusively.
///
/// [`Unavailable::NoMedium`] when the board has none or the SPI-NOR does not answer;
/// [`Unavailable::Busy`] when another path is holding it. The two are different answers to
/// a person: one is "this board cannot", the other is "not while that is happening".
pub fn area() -> Result<Area, Unavailable> {
    // Taken before the medium is brought up: a second holder must be told no rather than
    // handed a fresh view of the same bytes. This is what stops a USB offer overwriting an
    // image while the screen is still asking about it -- and, on a PSRAM board, what stops
    // it landing on a transaction somebody is signing.
    #[cfg(not(feature = "board-mk3"))]
    {
        let lease = crate::psram::take(crate::psram::Use::Upgrade).map_err(|why| match why {
            crate::psram::Unavailable::NoMedium => Unavailable::NoMedium,
            crate::psram::Unavailable::Busy(_) => Unavailable::Busy,
        })?;
        let psram = catcard_board::BOARD.psram.ok_or(Unavailable::NoMedium)?;
        // SAFETY: the region is the memory-mapped PSRAM the board table describes and
        // the lease taken above is what says nothing else in this firmware is writing
        // it. Whether it is actually mapped is what `Debug → PSRAM` proves; an unmapped
        // region shows up as a write that does not read back, which staging catches.
        let medium = unsafe { catcard_upgrade::psram::PsramArea::claim(&psram) };
        Ok(Area {
            medium,
            _lease: lease,
        })
    }
    #[cfg(feature = "board-mk3")]
    {
        let ticket = HELD.take(NOR_STAGING).ok_or(Unavailable::Busy)?;
        // SAFETY: SPI2 and the sflash pins belong to the SPI-NOR alone; the menu waits for
        // an upgrade to finish before this can run again.
        let nor = unsafe { crate::nor::init() }.ok_or(Unavailable::NoMedium)?;
        Ok(Area {
            medium: catcard_upgrade::nor::NorArea::new(nor),
            _ticket: ticket,
        })
    }
}

/// Install an image whose `commit` has already published its staging marker.
///
/// On mk4/mk5/Q1 this authorises the staged PSRAM region through `gate 18/7`, which does
/// **not** return on success (the bootloader installs and reboots); on a refusal it shows
/// why and returns. On mk3 the marker `commit` wrote is the whole trigger, so this just
/// reboots and the bootloader installs on boot — it never returns.
pub fn install(
    gate: &Callgate,
    login: &mut catcard_pin::Login,
    panel: &mut display::Panel,
    region: catcard_upgrade::Region,
) {
    #[cfg(feature = "board-mk3")]
    {
        // The trailing "upload complete" header was written into SPI-NOR by `commit`; the
        // bootloader's `sf_firmware_upgrade` finds it on boot and copies the image into
        // main flash. No gate 18/7, so `login`/`region` are unused here.
        let _ = (login, region);
        crate::catlog!("install: mk3 SPI-NOR staged, rebooting to install");
        crate::menu::message(panel, "Installing", "rebooting", "");
        // SAFETY: nothing after this runs; the bootloader clears SRAM.
        unsafe { gate.logout(LogoutMode::LogoutAndReboot) }
    }

    #[cfg(not(feature = "board-mk3"))]
    {
        let g = crate::pinentry::BootloaderGate::new(gate);
        crate::catlog!(
            "install: authorizing {:#010x} len {}",
            region.start,
            region.len
        );
        let why = match login.authorize_firmware(&g, region.start, region.len) {
            Ok(never) => match never {},
            // The bootloader ran its own verification and refused. That is a better answer
            // than ours: it is the check that actually gates the install.
            Err(catcard_pin::Failure::ImageRefused) => "bootloader refused it (gate 18/7 -112)",
            Err(catcard_pin::Failure::NeedsSetup) => "login went stale",
            Err(catcard_pin::Failure::MustWait) => "rate limited",
            Err(catcard_pin::Failure::Gate(_)) => "callgate unreachable",
            Err(catcard_pin::Failure::Code(c)) => {
                crate::catlog!("install: refused, gate code {}", c);
                "refused"
            }
        };
        // The panel may be the broken thing, so this goes in the log too -- the only place
        // a dark device can put it.
        crate::catlog!("install: NOT INSTALLED: {}", why);
        crate::menu::message(panel, "Not installed", why, "any key to go back");
    }
}
