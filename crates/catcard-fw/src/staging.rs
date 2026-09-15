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

#[cfg(feature = "board-mk3")]
use catcard_callgate::abi::LogoutMode;
use catcard_callgate::Callgate;

use crate::display;

/// The staging area type for this board: PSRAM on mk4/mk5/Q1, SPI-NOR on mk3.
#[cfg(not(feature = "board-mk3"))]
pub type Area = catcard_upgrade::psram::PsramArea;
#[cfg(feature = "board-mk3")]
pub type Area = catcard_upgrade::nor::NorArea<crate::nor::NorBus>;

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

/// Claim the board's firmware-staging area, if it has one and it is reachable.
///
/// `None` when the medium is absent (a board with neither PSRAM nor SPI-NOR) or, on mk3,
/// when the SPI-NOR does not answer — either way there is nowhere to stage an image, which
/// the caller reports rather than proceeding.
pub fn area() -> Option<Area> {
    #[cfg(not(feature = "board-mk3"))]
    {
        let psram = catcard_board::BOARD.psram?;
        // SAFETY: the region is the memory-mapped PSRAM the board table describes and
        // nothing else in this firmware writes it. Whether it is actually mapped is what
        // `Debug → PSRAM` proves; an unmapped region shows up as a write that does not
        // read back, which staging catches.
        Some(unsafe { catcard_upgrade::psram::PsramArea::claim(&psram) })
    }
    #[cfg(feature = "board-mk3")]
    {
        // SAFETY: SPI2 and the sflash pins belong to the SPI-NOR alone; the menu waits for
        // an upgrade to finish before this can run again.
        let nor = unsafe { crate::nor::init() }?;
        Some(catcard_upgrade::nor::NorArea::new(nor))
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
